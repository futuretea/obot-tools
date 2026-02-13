package main

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/obot-platform/tools/openai-model-provider/proxy"
)

func main() {
	apiKey := os.Getenv("OBOT_QWEN_MODEL_PROVIDER_API_KEY")
	if apiKey == "" {
		fmt.Println("OBOT_QWEN_MODEL_PROVIDER_API_KEY environment variable not set, credential must be provided on a per-request basis")
	}

	endpoint := os.Getenv("OBOT_QWEN_MODEL_PROVIDER_BASE_URL")
	if endpoint == "" {
		fmt.Println("OBOT_QWEN_MODEL_PROVIDER_BASE_URL environment variable not set, credential must be provided on a per-request basis")
	}

	endpoint = strings.TrimRight(endpoint, "/")
	u, err := url.Parse(endpoint)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid endpoint URL %q: %v\n", endpoint, err)
		os.Exit(1)
	}

	if u.Scheme == "" {
		if u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" {
			u.Scheme = "http"
		} else {
			u.Scheme = "https"
		}
	}

	enableThinking := strings.EqualFold(os.Getenv("OBOT_QWEN_MODEL_PROVIDER_ENABLE_THINKING"), "true")

	cfg := &proxy.Config{
		APIKey:                apiKey,
		PersonalAPIKeyHeader:  "X-Obot-OBOT_QWEN_MODEL_PROVIDER_API_KEY",
		PersonalBaseURLHeader: "X-Obot-OBOT_QWEN_MODEL_PROVIDER_BASE_URL",
		ListenPort:            os.Getenv("PORT"),
		BaseURL:               strings.TrimSuffix(u.String(), "/v1") + "/v1",
		RewriteModelsFn: proxy.RewriteAllModelsWithUsageMap(map[string][]func(string) bool{
			"text-embedding":  {func(id string) bool { return strings.Contains(strings.ToLower(id), "embedding") }},
			"image-generation": {func(id string) bool { return strings.Contains(strings.ToLower(id), "image") }},
			"llm": {func(id string) bool {
				lower := strings.ToLower(id)
				return !strings.Contains(lower, "embedding") && !strings.Contains(lower, "image")
			}},
		}),
		Name:                  "Qwen",
	}

	if enableThinking {
		// Ensure URL is parsed before creating the director.
		if err := cfg.EnsureURL(); err != nil {
			fmt.Fprintf(os.Stderr, "failed to parse base URL: %v\n", err)
			os.Exit(1)
		}
		cfg.CustomPathHandleFuncs = map[string]http.HandlerFunc{
			"/v1/chat/completions": thinkingMiddleware(enableThinking, &httputil.ReverseProxy{
				Director: newProxyDirector(cfg),
			}),
		}
	}

	if len(os.Args) > 1 && os.Args[1] == "validate" {
		if err := cfg.Validate("/tools/qwen-model-provider/validate"); err != nil {
			os.Exit(1)
		}
		return
	}

	if err := proxy.Run(cfg); err != nil {
		panic(err)
	}
}

// newProxyDirector creates a director function that mirrors the proxy package's proxyDirector.
// This duplication is necessary because the proxy package's director is unexported,
// and we need a custom reverse proxy to wrap with the thinking middleware.
func newProxyDirector(cfg *proxy.Config) func(req *http.Request) {
	return func(req *http.Request) {
		u := cfg.URL
		if baseURL := req.Header.Get(cfg.PersonalBaseURLHeader); baseURL != "" {
			if baseU, err := url.Parse(baseURL); err == nil {
				u = baseU
			}
		}
		req.URL.Scheme = u.Scheme
		req.URL.Host = u.Host
		req.URL.Path = u.JoinPath(strings.TrimPrefix(req.URL.Path, "/v1")).Path
		req.Host = req.URL.Host

		apiKey := cfg.APIKey
		if requestAPIKey := req.Header.Get(cfg.PersonalAPIKeyHeader); requestAPIKey != "" {
			apiKey = requestAPIKey
			req.Header.Del(cfg.PersonalAPIKeyHeader)
		}
		req.Header.Set("Authorization", "Bearer "+apiKey)

		if cfg.RewriteHeaderFn != nil {
			cfg.RewriteHeaderFn(req.Header)
		}
	}
}
