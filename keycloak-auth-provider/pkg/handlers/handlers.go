package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	oauth2proxy "github.com/oauth2-proxy/oauth2-proxy/v7"

	"github.com/obot-platform/tools/auth-providers-common/pkg/icon"
	"github.com/obot-platform/tools/auth-providers-common/pkg/state"
	"github.com/obot-platform/tools/keycloak-auth-provider/pkg/client"
	"github.com/obot-platform/tools/keycloak-auth-provider/pkg/config"
	"github.com/obot-platform/tools/keycloak-auth-provider/pkg/profile"
)

const bearerPrefix = "Bearer "

// groupClaimNames defines JWT claim names for group membership (checked in order)
var groupClaimNames = []string{"groups", "full_group_path"}

// Handlers provides HTTP handlers for keycloak-auth-provider endpoints
type Handlers struct {
	oauthProxy    *oauth2proxy.OAuthProxy
	config        *config.Config
	serviceClient *client.ServiceAccountClient
}

// New creates a Handlers instance with the given OAuth proxy and configuration
func New(oauthProxy *oauth2proxy.OAuthProxy, cfg *config.Config) *Handlers {
	return &Handlers{
		oauthProxy:    oauthProxy,
		config:        cfg,
		serviceClient: client.NewServiceAccountClient(cfg.IssuerURL, cfg.ClientID, cfg.ClientSecret),
	}
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

// Compile-time interface verification
var _ http.ResponseWriter = (*responseWriter)(nil)

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// LoggingMiddleware returns a middleware that logs all incoming requests at DEBUG level
func (h *Handlers) LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !h.config.Debug {
			next.ServeHTTP(w, r)
			return
		}

		start := time.Now()

		// Log request details
		h.logDebug(">>> %s %s", r.Method, r.URL.String())
		h.logDebug("    Host: %s", r.Host)
		h.logDebug("    RemoteAddr: %s", r.RemoteAddr)

		// Log selected headers (avoid logging sensitive data in full)
		for _, header := range []string{"Content-Type", "User-Agent", "X-Forwarded-For", "X-Real-IP"} {
			if v := r.Header.Get(header); v != "" {
				h.logDebug("    %s: %s", header, v)
			}
		}

		// Log Authorization header presence (not the value)
		if auth := r.Header.Get("Authorization"); auth != "" {
			authType := strings.SplitN(auth, " ", 2)[0]
			h.logDebug("    Authorization: %s [REDACTED]", authType)
		}

		// Log Cookie header presence (not the value)
		if cookies := r.Header.Get("Cookie"); cookies != "" {
			h.logDebug("    Cookie: [REDACTED, length=%d]", len(cookies))
		}

		// Wrap response writer to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(wrapped, r)

		// Log response
		h.logDebug("<<< %s %s -> %d (%v)", r.Method, r.URL.Path, wrapped.statusCode, time.Since(start))
	})
}

// Root returns the provider's local URL for service discovery
func (h *Handlers) Root(w http.ResponseWriter, _ *http.Request) {
	fmt.Fprintf(w, "http://127.0.0.1:%s", h.config.Port)
}

// GetState returns the current session state including user groups.
// Groups are extracted using two strategies:
//  1. Parse groups from ID token claims (primary, faster)
//  2. Fetch from UserInfo endpoint (fallback)
func (h *Handlers) GetState(w http.ResponseWriter, r *http.Request) {
	var sr state.SerializableRequest
	if err := json.NewDecoder(r.Body).Decode(&sr); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	reqObj, err := http.NewRequest(sr.Method, sr.URL, nil)
	if err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	reqObj.Header = sr.Header

	ss, err := state.GetSerializableState(h.oauthProxy, reqObj)
	if err != nil {
		http.Error(w, "authentication failed", http.StatusInternalServerError)
		h.logError("get state: %v", err)
		return
	}

	ss.GroupInfos = h.extractUserGroups(r.Context(), ss)

	if err := json.NewEncoder(w).Encode(ss); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		h.logError("encode state: %v", err)
	}
}

// extractUserGroups retrieves user groups from ID token or UserInfo endpoint
func (h *Handlers) extractUserGroups(ctx context.Context, ss state.SerializableState) []state.GroupInfo {
	// Strategy 1: Parse groups from ID token (primary, no network call)
	if ss.IDToken != "" {
		if groups := parseIDTokenForGroups(ss.IDToken); len(groups) > 0 {
			h.logDebug("ID token groups: %v", groups)
			return toGroupInfos(groups)
		}
	}

	// Strategy 2: Fallback to UserInfo endpoint
	if ss.AccessToken == "" {
		return nil
	}

	h.logDebug("fetching groups from UserInfo: %s", h.config.UserInfoURL())
	userInfo, err := profile.FetchKeycloakProfile(ctx, bearerPrefix+ss.AccessToken, h.config.UserInfoURL())
	if err != nil {
		h.logWarn("fetch groups from userinfo: %v", err)
		return nil
	}

	h.logDebug("UserInfo groups: %v", userInfo.Groups)
	return userInfo.GroupInfos()
}

// GetUserInfo fetches user profile from Keycloak's UserInfo endpoint
func (h *Handlers) GetUserInfo(w http.ResponseWriter, r *http.Request) {
	userInfo, err := profile.FetchKeycloakProfile(r.Context(), r.Header.Get("Authorization"), h.config.UserInfoURL())
	if err != nil {
		http.Error(w, "failed to fetch user info", http.StatusBadRequest)
		return
	}
	_ = json.NewEncoder(w).Encode(userInfo)
}

// ListAuthGroups lists all available groups from Keycloak Admin API.
// Uses client credentials flow (service account) to access Admin API.
// Returns empty list if group search is disabled or on any error.
func (h *Handlers) ListAuthGroups(w http.ResponseWriter, r *http.Request) {
	emptyGroups := []state.GroupInfo{}

	if !h.config.GroupSearchEnabled {
		h.logDebug("group search disabled")
		h.writeJSON(w, emptyGroups)
		return
	}

	kc, err := h.serviceClient.GetAdminClient(r.Context())
	if err != nil {
		h.logWarn("get admin client: %v", err)
		h.writeJSON(w, emptyGroups)
		return
	}

	groups, err := kc.ListAllGroups(r.Context())
	if err != nil {
		h.logWarn("list groups from Admin API: %v", err)
		h.writeJSON(w, emptyGroups)
		return
	}

	h.logDebug("raw groups from API: %d top-level", len(groups))

	flatGroups := client.FlattenGroups(groups)
	groupInfos := make([]state.GroupInfo, len(flatGroups))
	for i, g := range flatGroups {
		groupInfos[i] = state.GroupInfo{ID: g.Path, Name: g.Name}
	}

	h.logDebug("total groups after flattening: %d", len(groupInfos))
	h.writeJSON(w, groupInfos)
}

// ListUserAuthGroups is a no-op placeholder for per-user group listing.
// Keycloak Admin API requires special permissions for this operation,
// so we return an empty list. The request body is discarded.
func (h *Handlers) ListUserAuthGroups(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
	h.writeJSON(w, []state.GroupInfo{})
}

// GetIconURL returns a handler that fetches the user's profile picture URL
func (h *Handlers) GetIconURL() http.HandlerFunc {
	return icon.ObotGetIconURL(func(ctx context.Context, accessToken string) (string, error) {
		userInfo, err := profile.FetchKeycloakProfile(ctx, bearerPrefix+accessToken, h.config.UserInfoURL())
		if err != nil {
			return "", err
		}
		return userInfo.Picture, nil
	})
}

// OAuthProxyHandler returns the underlying oauth2-proxy HTTP handler
func (h *Handlers) OAuthProxyHandler() http.HandlerFunc {
	return h.oauthProxy.ServeHTTP
}

// writeJSON encodes v as JSON to the response writer
func (h *Handlers) writeJSON(w http.ResponseWriter, v any) {
	_ = json.NewEncoder(w).Encode(v)
}

func (h *Handlers) logDebug(format string, args ...any) {
	if h.config.Debug {
		fmt.Printf("DEBUG: keycloak-auth-provider: "+format+"\n", args...)
	}
}

func (h *Handlers) logWarn(format string, args ...any) {
	fmt.Printf("WARN: keycloak-auth-provider: "+format+"\n", args...)
}

func (h *Handlers) logError(format string, args ...any) {
	fmt.Printf("ERROR: keycloak-auth-provider: "+format+"\n", args...)
}

// toGroupInfos converts group paths to GroupInfo slice using path as both ID and Name
func toGroupInfos(paths []string) []state.GroupInfo {
	result := make([]state.GroupInfo, len(paths))
	for i, path := range paths {
		result[i] = state.GroupInfo{ID: path, Name: path}
	}
	return result
}

// parseIDTokenForGroups extracts groups from ID token without validation.
// Checks groupClaimNames in order and returns first non-empty result.
func parseIDTokenForGroups(idToken string) []string {
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(idToken, jwt.MapClaims{})
	if err != nil {
		return nil
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil
	}

	for _, claimName := range groupClaimNames {
		if groups := extractStringSlice(claims, claimName); len(groups) > 0 {
			return groups
		}
	}
	return nil
}

// extractStringSlice safely extracts a string slice from JWT claims
func extractStringSlice(claims jwt.MapClaims, key string) []string {
	arr, ok := claims[key].([]interface{})
	if !ok {
		return nil
	}
	result := make([]string, 0, len(arr))
	for _, v := range arr {
		if s, ok := v.(string); ok {
			result = append(result, s)
		}
	}
	return result
}
