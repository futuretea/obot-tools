package profile

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/obot-platform/tools/auth-providers-common/pkg/state"
)

const defaultTimeout = 30 * time.Second

// httpClient is a shared HTTP client with timeout for all profile requests.
// Using a shared client enables connection reuse.
var httpClient = &http.Client{Timeout: defaultTimeout}

// KeycloakProfile represents user profile data from Keycloak's UserInfo endpoint.
// Fields follow the OIDC standard claims plus Keycloak-specific extensions.
type KeycloakProfile struct {
	Sub               string   `json:"sub"`
	Email             string   `json:"email"`
	EmailVerified     bool     `json:"email_verified"`
	PreferredUsername string   `json:"preferred_username"`
	Name              string   `json:"name"`
	GivenName         string   `json:"given_name"`
	FamilyName        string   `json:"family_name"`
	Picture           string   `json:"picture"`
	Groups            []string `json:"groups"`
	FullGroupPath     []string `json:"full_group_path"`
}

// GroupInfos returns the user's groups as state.GroupInfo slice.
// Prefers FullGroupPath over Groups as it contains the full hierarchy path.
func (p *KeycloakProfile) GroupInfos() []state.GroupInfo {
	groups := p.FullGroupPath
	if len(groups) == 0 {
		groups = p.Groups
	}
	return pathsToGroupInfos(groups)
}

// pathsToGroupInfos converts group paths to GroupInfo slice
func pathsToGroupInfos(paths []string) []state.GroupInfo {
	if len(paths) == 0 {
		return nil
	}
	result := make([]state.GroupInfo, len(paths))
	for i, path := range paths {
		result[i] = state.GroupInfo{ID: path, Name: path}
	}
	return result
}

// FetchKeycloakProfile retrieves user profile from Keycloak's UserInfo endpoint.
// The accessToken should include the "Bearer " prefix.
func FetchKeycloakProfile(ctx context.Context, accessToken, url string) (*KeycloakProfile, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	if accessToken != "" {
		req.Header.Set("Authorization", accessToken)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch profile: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("userinfo returned status %d: %s", resp.StatusCode, body)
	}

	var profile KeycloakProfile
	if err := json.NewDecoder(resp.Body).Decode(&profile); err != nil {
		return nil, fmt.Errorf("decode profile: %w", err)
	}

	return &profile, nil
}
