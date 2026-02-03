package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/obot-platform/tools/auth-providers-common/pkg/env"
)

// Environment variable names
const (
	envPort               = "PORT"
	envIssuerURL          = "OAUTH2_PROXY_OIDC_ISSUER_URL"
	envToolDir            = "GPTSCRIPT_TOOL_DIR"
	envDebug              = "OBOT_AUTH_DEBUG"
	envGroupSearchEnabled = "OBOT_KEYCLOAK_GROUP_SEARCH_ENABLED"
)

// Default values
const (
	defaultPort            = "9999"
	templatesRelativePath  = "/../auth-providers-common/templates"
	userInfoEndpointSuffix = "/protocol/openid-connect/userinfo"
)

// ErrMissingIssuerURL indicates the OIDC issuer URL is not configured
var ErrMissingIssuerURL = errors.New(envIssuerURL + " is required but not set")

// Options contains raw configuration from environment variables
type Options struct {
	ClientID                 string `env:"OBOT_KEYCLOAK_AUTH_PROVIDER_CLIENT_ID"`
	ClientSecret             string `env:"OBOT_KEYCLOAK_AUTH_PROVIDER_CLIENT_SECRET"`
	ObotServerURL            string `env:"OBOT_SERVER_PUBLIC_URL,OBOT_SERVER_URL"`
	PostgresConnectionDSN    string `env:"OBOT_AUTH_PROVIDER_POSTGRES_CONNECTION_DSN" optional:"true"`
	AuthCookieSecret         string `env:"OBOT_AUTH_PROVIDER_COOKIE_SECRET"`
	AuthEmailDomains         string `env:"OBOT_AUTH_PROVIDER_EMAIL_DOMAINS" default:"*"`
	AuthTokenRefreshDuration string `env:"OBOT_AUTH_PROVIDER_TOKEN_REFRESH_DURATION" default:"1h" optional:"true"`
}

// Config is the parsed and validated configuration
type Config struct {
	ClientID              string
	ClientSecret          string
	ObotServerURL         string
	PostgresConnectionDSN string
	CookieSecret          []byte
	EmailDomains          []string
	TokenRefreshDuration  time.Duration
	GroupSearchEnabled    bool
	Debug                 bool
	Port                  string
	IssuerURL             string
	TemplatesPath         string
}

// LoadFromEnv loads and validates configuration from environment variables
func LoadFromEnv() (*Config, error) {
	var opts Options
	if err := env.LoadEnvForStruct(&opts); err != nil {
		return nil, fmt.Errorf("load options: %w", err)
	}

	refreshDuration, err := time.ParseDuration(opts.AuthTokenRefreshDuration)
	if err != nil {
		return nil, fmt.Errorf("parse token refresh duration %q: %w", opts.AuthTokenRefreshDuration, err)
	}
	if refreshDuration < 0 {
		return nil, errors.New("token refresh duration must be positive")
	}

	cookieSecret, err := base64.StdEncoding.DecodeString(opts.AuthCookieSecret)
	if err != nil {
		return nil, fmt.Errorf("decode cookie secret: %w", err)
	}

	issuerURL := os.Getenv(envIssuerURL)
	if issuerURL == "" {
		return nil, ErrMissingIssuerURL
	}

	return &Config{
		ClientID:              opts.ClientID,
		ClientSecret:          opts.ClientSecret,
		ObotServerURL:         opts.ObotServerURL,
		PostgresConnectionDSN: opts.PostgresConnectionDSN,
		CookieSecret:          cookieSecret,
		EmailDomains:          parseEmailDomains(opts.AuthEmailDomains),
		TokenRefreshDuration:  refreshDuration,
		GroupSearchEnabled:    os.Getenv(envGroupSearchEnabled) != "false",
		Debug:                 os.Getenv(envDebug) == "true",
		Port:                  getEnvOrDefault(envPort, defaultPort),
		IssuerURL:             issuerURL,
		TemplatesPath:         os.Getenv(envToolDir) + templatesRelativePath,
	}, nil
}

func getEnvOrDefault(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

func parseEmailDomains(domains string) []string {
	if domains == "" {
		return nil
	}
	parts := strings.Split(domains, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// UserInfoURL returns the OIDC UserInfo endpoint URL
func (c *Config) UserInfoURL() string {
	return strings.TrimRight(c.IssuerURL, "/") + userInfoEndpointSuffix
}
