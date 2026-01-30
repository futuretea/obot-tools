package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Sentinel errors for Keycloak API responses
var (
	ErrAccessDenied = errors.New("access denied: user lacks required Keycloak roles")
	ErrUnauthorized = errors.New("unauthorized: invalid or expired token")
)

const (
	defaultTimeout     = 30 * time.Second
	tokenExpiryBuffer  = 30 * time.Second
	bearerPrefix       = "Bearer "
	contentTypeJSON    = "application/json"
)

// Group represents a Keycloak group from Admin API
type Group struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Path      string  `json:"path"`
	Subgroups []Group `json:"subGroups"`
}

// User represents a Keycloak user from Admin API
type User struct {
	ID            string `json:"id"`
	Username      string `json:"username"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"emailVerified"`
	FirstName     string `json:"firstName"`
	LastName      string `json:"lastName"`
	Enabled       bool   `json:"enabled"`
}

// tokenResponse represents the OAuth2 token endpoint response
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// ServiceAccountClient manages client credentials flow for Admin API access
type ServiceAccountClient struct {
	httpClient   *http.Client
	tokenURL     string
	clientID     string
	clientSecret string
	issuerURL    string

	mu          sync.RWMutex
	cachedToken string
	expiresAt   time.Time
}

// NewServiceAccountClient creates a client for Admin API using client credentials flow
func NewServiceAccountClient(issuerURL, clientID, clientSecret string) *ServiceAccountClient {
	tokenURL := strings.TrimRight(issuerURL, "/") + "/protocol/openid-connect/token"
	return &ServiceAccountClient{
		httpClient:   &http.Client{Timeout: defaultTimeout},
		tokenURL:     tokenURL,
		clientID:     clientID,
		clientSecret: clientSecret,
		issuerURL:    issuerURL,
	}
}

// GetAdminClient returns a Client for Admin API using cached or fresh service account token
func (s *ServiceAccountClient) GetAdminClient(ctx context.Context) (*Client, error) {
	token, err := s.getToken(ctx)
	if err != nil {
		return nil, err
	}
	return New(token, s.issuerURL)
}

// getToken returns a cached token if valid, or fetches a new one
func (s *ServiceAccountClient) getToken(ctx context.Context) (string, error) {
	s.mu.RLock()
	if s.cachedToken != "" && time.Now().Before(s.expiresAt) {
		token := s.cachedToken
		s.mu.RUnlock()
		return token, nil
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()

	// Double-check after acquiring write lock
	if s.cachedToken != "" && time.Now().Before(s.expiresAt) {
		return s.cachedToken, nil
	}

	token, expiresIn, err := s.fetchToken(ctx)
	if err != nil {
		return "", err
	}

	s.cachedToken = token
	s.expiresAt = time.Now().Add(time.Duration(expiresIn)*time.Second - tokenExpiryBuffer)
	return token, nil
}

// fetchToken performs the client credentials grant request
func (s *ServiceAccountClient) fetchToken(ctx context.Context) (string, int, error) {
	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {s.clientID},
		"client_secret": {s.clientSecret},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", 0, fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, fmt.Errorf("read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", 0, fmt.Errorf("parse token response: %w", err)
	}

	if tr.AccessToken == "" {
		return "", 0, errors.New("empty access token in response")
	}

	return tr.AccessToken, tr.ExpiresIn, nil
}

// Client is an HTTP client for Keycloak Admin API
type Client struct {
	httpClient  *http.Client
	adminURL    string
	accessToken string
}

// New creates a new Keycloak Admin API client
func New(accessToken, issuerURL string) (*Client, error) {
	adminURL, err := buildAdminURL(issuerURL)
	if err != nil {
		return nil, err
	}

	return &Client{
		httpClient:  &http.Client{Timeout: defaultTimeout},
		adminURL:    adminURL,
		accessToken: normalizeToken(accessToken),
	}, nil
}

// normalizeToken ensures the token has the Bearer prefix
func normalizeToken(token string) string {
	if token == "" || strings.HasPrefix(token, bearerPrefix) {
		return token
	}
	return bearerPrefix + token
}

// buildAdminURL converts issuer URL to Admin API URL
// https://keycloak.example.com/realms/myrealm → https://keycloak.example.com/admin/realms/myrealm
// https://keycloak.example.com/auth/realms/myrealm → https://keycloak.example.com/auth/admin/realms/myrealm (Keycloak < 19)
func buildAdminURL(issuerURL string) (string, error) {
	// Keycloak < 19 has /auth/ prefix
	if parts := strings.SplitAfter(issuerURL, "/auth/"); len(parts) == 2 {
		return parts[0] + "admin/" + parts[1], nil
	}

	// Keycloak >= 19 doesn't have /auth/ prefix
	if parts := strings.SplitN(issuerURL, "/realms/", 2); len(parts) == 2 {
		return parts[0] + "/admin/realms/" + parts[1], nil
	}

	return "", fmt.Errorf("cannot parse issuer URL: %s", issuerURL)
}

// get performs a GET request to Keycloak Admin API and returns the response body
func (c *Client) get(ctx context.Context, endpoint string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.adminURL+endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Accept", contentTypeJSON)
	if c.accessToken != "" {
		req.Header.Set("Authorization", c.accessToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
		return body, nil
	case http.StatusForbidden:
		return nil, ErrAccessDenied
	case http.StatusUnauthorized:
		return nil, ErrUnauthorized
	default:
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}
}

// ListAllGroups fetches all groups from Keycloak Admin API (matches Rancher's implementation)
func (c *Client) ListAllGroups(ctx context.Context) ([]Group, error) {
	return c.SearchGroups(ctx, "")
}

// SearchGroups searches groups by name
func (c *Client) SearchGroups(ctx context.Context, searchTerm string) ([]Group, error) {
	body, err := c.get(ctx, "/groups?search="+url.QueryEscape(searchTerm))
	if err != nil {
		return nil, err
	}

	var groups []Group
	if err := json.Unmarshal(body, &groups); err != nil {
		return nil, fmt.Errorf("parse groups: %w", err)
	}
	return groups, nil
}

// SearchUsers searches users by username, email, or name
func (c *Client) SearchUsers(ctx context.Context, searchTerm string) ([]User, error) {
	body, err := c.get(ctx, "/users?search="+url.QueryEscape(searchTerm))
	if err != nil {
		return nil, err
	}

	var users []User
	if err := json.Unmarshal(body, &users); err != nil {
		return nil, fmt.Errorf("parse users: %w", err)
	}
	return users, nil
}

// GetGroupByID fetches a single group by ID
func (c *Client) GetGroupByID(ctx context.Context, groupID string) (*Group, error) {
	body, err := c.get(ctx, "/groups/"+url.PathEscape(groupID))
	if err != nil {
		return nil, err
	}

	var group Group
	if err := json.Unmarshal(body, &group); err != nil {
		return nil, fmt.Errorf("parse group: %w", err)
	}
	return &group, nil
}

// FlattenGroups flattens a hierarchical group tree into a flat slice.
// Uses iterative DFS to avoid stack overflow on deeply nested groups.
func FlattenGroups(groups []Group) []Group {
	if len(groups) == 0 {
		return nil
	}

	// Estimate capacity: assume average 2x expansion for subgroups
	result := make([]Group, 0, len(groups)*2)
	stack := make([]Group, len(groups))
	copy(stack, groups)

	for len(stack) > 0 {
		g := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		result = append(result, g)

		// Push subgroups in reverse order to maintain original order
		for i := len(g.Subgroups) - 1; i >= 0; i-- {
			stack = append(stack, g.Subgroups[i])
		}
	}
	return result
}
