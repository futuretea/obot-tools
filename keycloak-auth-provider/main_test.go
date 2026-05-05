package main

import (
	"testing"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/obot-platform/tools/keycloak-auth-provider/pkg/config"
)

func TestConfigureCookieSetsCSRFExpireToThirtyMinutes(t *testing.T) {
	opts := options.NewOptions()
	cfg := &config.Config{
		CookieSecret:         []byte("0123456789abcdef0123456789abcdef"),
		ObotServerURL:        "http://localhost:8080",
		TokenRefreshDuration: time.Hour,
	}

	configureCookie(opts, cfg)

	if opts.Cookie.CSRFExpire != 30*time.Minute {
		t.Fatalf("expected CSRFExpire to be 30 minutes, got %s", opts.Cookie.CSRFExpire)
	}
}
