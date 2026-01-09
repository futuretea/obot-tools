package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	oauth2proxy "github.com/oauth2-proxy/oauth2-proxy/v7"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/validation"
	"github.com/obot-platform/tools/auth-providers-common/pkg/env"
	"github.com/obot-platform/tools/auth-providers-common/pkg/state"
	"github.com/obot-platform/tools/keycloak-auth-provider/pkg/profile"
)

type Options struct {
	ClientID                 string `env:"OBOT_KEYCLOAK_AUTH_PROVIDER_CLIENT_ID"`
	ClientSecret             string `env:"OBOT_KEYCLOAK_AUTH_PROVIDER_CLIENT_SECRET"`
	ObotServerURL            string `env:"OBOT_SERVER_PUBLIC_URL,OBOT_SERVER_URL"`
	PostgresConnectionDSN    string `env:"OBOT_AUTH_PROVIDER_POSTGRES_CONNECTION_DSN" optional:"true"`
	AuthCookieSecret         string `usage:"Secret used to encrypt cookie" env:"OBOT_AUTH_PROVIDER_COOKIE_SECRET"`
	AuthEmailDomains         string `usage:"Email domains allowed for authentication" default:"*" env:"OBOT_AUTH_PROVIDER_EMAIL_DOMAINS"`
	AuthTokenRefreshDuration string `usage:"Duration to refresh auth token after" optional:"true" default:"1h" env:"OBOT_AUTH_PROVIDER_TOKEN_REFRESH_DURATION"`
}

func main() {
	var opts Options
	if err := env.LoadEnvForStruct(&opts); err != nil {
		fmt.Printf("ERROR: keycloak-auth-provider: failed to load options: %v\n", err)
		os.Exit(1)
	}

	refreshDuration, err := time.ParseDuration(opts.AuthTokenRefreshDuration)
	if err != nil {
		fmt.Printf("ERROR: keycloak-auth-provider: failed to parse token refresh duration: %v\n", err)
		os.Exit(1)
	}

	if refreshDuration < 0 {
		fmt.Printf("ERROR: keycloak-auth-provider: token refresh duration must be greater than 0\n")
		os.Exit(1)
	}

	cookieSecret, err := base64.StdEncoding.DecodeString(opts.AuthCookieSecret)
	if err != nil {
		fmt.Printf("ERROR: keycloak-auth-provider: failed to decode cookie secret: %v\n", err)
		os.Exit(1)
	}

	legacyOpts := options.NewLegacyOptions()

	// Load any OAUTH2_PROXY_* environment variables (for example, OIDC issuer URL)
	if err := options.Load("", options.NewLegacyFlagSet(), legacyOpts); err != nil {
		fmt.Printf("ERROR: keycloak-auth-provider: failed to load oauth2-proxy options: %v\n", err)
		os.Exit(1)
	}

	legacyOpts.LegacyProvider.ProviderType = "keycloak-oidc"
	legacyOpts.LegacyProvider.ProviderName = "keycloak"
	legacyOpts.LegacyProvider.ClientID = opts.ClientID
	legacyOpts.LegacyProvider.ClientSecret = opts.ClientSecret

	oauthProxyOpts, err := legacyOpts.ToOptions()
	if err != nil {
		fmt.Printf("ERROR: keycloak-auth-provider: failed to convert legacy options to new options: %v\n", err)
		os.Exit(1)
	}

	oauthProxyOpts.Server.BindAddress = ""
	oauthProxyOpts.MetricsServer.BindAddress = ""
	if opts.PostgresConnectionDSN != "" {
		oauthProxyOpts.Session.Type = options.PostgresSessionStoreType
		oauthProxyOpts.Session.Postgres.ConnectionDSN = opts.PostgresConnectionDSN
		oauthProxyOpts.Session.Postgres.TableNamePrefix = "keycloak_"
	}
	oauthProxyOpts.Cookie.Refresh = refreshDuration
	oauthProxyOpts.Cookie.Name = "obot_access_token"
	oauthProxyOpts.Cookie.Secret = string(bytes.TrimSpace(cookieSecret))
	oauthProxyOpts.Cookie.Secure = strings.HasPrefix(opts.ObotServerURL, "https://")
	oauthProxyOpts.Cookie.CSRFExpire = 30 * time.Minute
	oauthProxyOpts.Templates.Path = os.Getenv("GPTSCRIPT_TOOL_DIR") + "/../auth-providers-common/templates"
	oauthProxyOpts.RawRedirectURL = opts.ObotServerURL + "/"
	if opts.AuthEmailDomains != "" {
		emailDomains := strings.Split(opts.AuthEmailDomains, ",")
		for i := range emailDomains {
			emailDomains[i] = strings.TrimSpace(emailDomains[i])
		}
		oauthProxyOpts.EmailDomains = emailDomains
	}
	oauthProxyOpts.Logging.RequestEnabled = false
	oauthProxyOpts.Logging.AuthEnabled = false
	oauthProxyOpts.Logging.StandardEnabled = false

	if err = validation.Validate(oauthProxyOpts); err != nil {
		fmt.Printf("ERROR: keycloak-auth-provider: failed to validate options: %v\n", err)
		os.Exit(1)
	}

	oauthProxy, err := oauth2proxy.NewOAuthProxy(oauthProxyOpts, oauth2proxy.NewValidator(oauthProxyOpts.EmailDomains, oauthProxyOpts.AuthenticatedEmailsFile))
	if err != nil {
		fmt.Printf("ERROR: keycloak-auth-provider: failed to create oauth2 proxy: %v\n", err)
		os.Exit(1)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "9999"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(fmt.Sprintf("http://127.0.0.1:%s", port)))
	})
	mux.HandleFunc("/obot-get-state", state.ObotGetState(oauthProxy))
	mux.HandleFunc("/obot-get-user-info", func(w http.ResponseWriter, r *http.Request) {
		issuerURL := os.Getenv("OAUTH2_PROXY_OIDC_ISSUER_URL")
		if issuerURL == "" {
			http.Error(w, "OAUTH2_PROXY_OIDC_ISSUER_URL is not set", http.StatusInternalServerError)
			return
		}

		userInfoURL := strings.TrimRight(issuerURL, "/") + "/protocol/openid-connect/userinfo"

		userInfo, err := profile.FetchKeycloakProfile(r.Context(), r.Header.Get("Authorization"), userInfoURL)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to fetch user info: %v", err), http.StatusBadRequest)
			return
		}

		json.NewEncoder(w).Encode(userInfo)
	})
	mux.HandleFunc("/obot-list-user-auth-groups", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/", oauthProxy.ServeHTTP)

	fmt.Printf("listening on 127.0.0.1:%s\n", port)
	if err := http.ListenAndServe("127.0.0.1:"+port, mux); !errors.Is(err, http.ErrServerClosed) {
		fmt.Printf("ERROR: keycloak-auth-provider: failed to listen and serve: %v\n", err)
		os.Exit(1)
	}
}
