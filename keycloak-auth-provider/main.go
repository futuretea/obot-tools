package main

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	oauth2proxy "github.com/oauth2-proxy/oauth2-proxy/v7"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/validation"

	"github.com/obot-platform/tools/keycloak-auth-provider/pkg/config"
	"github.com/obot-platform/tools/keycloak-auth-provider/pkg/handlers"
)

const (
	providerType    = "keycloak-oidc"
	providerName    = "keycloak"
	cookieName      = "obot_access_token"
	sessionTablePfx = "keycloak_"
	csrfExpire      = 30 * time.Minute
	listenHost      = "127.0.0.1"
)

func main() {
	if err := run(); err != nil {
		fmt.Printf("ERROR: keycloak-auth-provider: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.LoadFromEnv()
	if err != nil {
		return err
	}

	oauthProxy, err := newOAuthProxy(cfg)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	h := handlers.New(oauthProxy, cfg)
	registerRoutes(mux, h)

	// Wrap mux with logging middleware
	handler := h.LoggingMiddleware(mux)

	addr := listenHost + ":" + cfg.Port
	fmt.Printf("listening on %s\n", addr)

	if err := http.ListenAndServe(addr, handler); !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("listen and serve: %w", err)
	}
	return nil
}

func registerRoutes(mux *http.ServeMux, h *handlers.Handlers) {
	mux.HandleFunc("/{$}", h.Root)
	mux.HandleFunc("/obot-get-state", h.GetState)
	mux.HandleFunc("/obot-get-user-info", h.GetUserInfo)
	mux.HandleFunc("/obot-list-auth-groups", h.ListAuthGroups)
	mux.HandleFunc("/obot-list-user-auth-groups", h.ListUserAuthGroups)
	mux.HandleFunc("/obot-get-icon-url", h.GetIconURL())
	mux.HandleFunc("/", h.OAuthProxyHandler())
}

func newOAuthProxy(cfg *config.Config) (*oauth2proxy.OAuthProxy, error) {
	legacyOpts := options.NewLegacyOptions()

	if err := options.Load("", options.NewLegacyFlagSet(), legacyOpts); err != nil {
		return nil, fmt.Errorf("load oauth2-proxy options: %w", err)
	}

	legacyOpts.LegacyProvider.ProviderType = providerType
	legacyOpts.LegacyProvider.ProviderName = providerName
	legacyOpts.LegacyProvider.ClientID = cfg.ClientID
	legacyOpts.LegacyProvider.ClientSecret = cfg.ClientSecret

	opts, err := legacyOpts.ToOptions()
	if err != nil {
		return nil, fmt.Errorf("convert legacy options: %w", err)
	}

	configureServer(opts)
	configureSession(opts, cfg)
	configureCookie(opts, cfg)
	configureTemplates(opts, cfg)

	opts.EmailDomains = cfg.EmailDomains
	opts.Logging.RequestEnabled = false
	opts.Logging.AuthEnabled = false
	opts.Logging.StandardEnabled = false

	if err := validation.Validate(opts); err != nil {
		return nil, fmt.Errorf("validate options: %w", err)
	}

	proxy, err := oauth2proxy.NewOAuthProxy(opts, oauth2proxy.NewValidator(opts.EmailDomains, opts.AuthenticatedEmailsFile))
	if err != nil {
		return nil, fmt.Errorf("create oauth2 proxy: %w", err)
	}

	return proxy, nil
}

func configureServer(opts *options.Options) {
	opts.Server.BindAddress = ""
	opts.MetricsServer.BindAddress = ""
}

func configureSession(opts *options.Options, cfg *config.Config) {
	if cfg.PostgresConnectionDSN == "" {
		return
	}
	opts.Session.Type = options.PostgresSessionStoreType
	opts.Session.Postgres.ConnectionDSN = cfg.PostgresConnectionDSN
	opts.Session.Postgres.TableNamePrefix = sessionTablePfx
}

func configureCookie(opts *options.Options, cfg *config.Config) {
	opts.Cookie.Refresh = cfg.TokenRefreshDuration
	opts.Cookie.Name = cookieName
	opts.Cookie.Secret = string(bytes.TrimSpace(cfg.CookieSecret))
	opts.Cookie.Secure = strings.HasPrefix(cfg.ObotServerURL, "https://")
	opts.Cookie.CSRFExpire = csrfExpire
}

func configureTemplates(opts *options.Options, cfg *config.Config) {
	opts.Templates.Path = cfg.TemplatesPath
	opts.RawRedirectURL = cfg.ObotServerURL + "/"
}
