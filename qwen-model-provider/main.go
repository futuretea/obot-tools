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

	baseURL, err := normalizeEndpoint(endpoint)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid endpoint URL %q: %v\n", endpoint, err)
		os.Exit(1)
	}

	cfg := &proxy.Config{
		APIKey:                apiKey,
		PersonalAPIKeyHeader:  "X-Obot-OBOT_QWEN_MODEL_PROVIDER_API_KEY",
		PersonalBaseURLHeader: "X-Obot-OBOT_QWEN_MODEL_PROVIDER_BASE_URL",
		ListenPort:            os.Getenv("PORT"),
		BaseURL:               baseURL,
		RewriteModelsFn: proxy.RewriteAllModelsWithUsageMap(map[string][]func(string) bool{
			"text-embedding": {func(id string) bool { return strings.Contains(strings.ToLower(id), "embedding") }},
			"image-generation": {func(id string) bool {
				lower := strings.ToLower(id)
				return strings.Contains(lower, "image") || strings.Contains(lower, "stable-diffusion")
			}},
			"vision": {func(id string) bool { return strings.Contains(strings.ToLower(id), "-vl") }},
			"llm": {func(id string) bool {
				lower := strings.ToLower(id)
				return !strings.Contains(lower, "embedding") &&
					!strings.Contains(lower, "image") &&
					!strings.Contains(lower, "stable-diffusion") &&
					!strings.Contains(lower, "-vl")
			}},
		}),
		Name: "Qwen",
	}

	if len(os.Args) > 1 && os.Args[1] == "validate" {
		if err := cfg.Validate("/tools/qwen-model-provider/validate"); err != nil {
			os.Exit(1)
		}
		return
	}

	// Register thinking middleware only when the env var is explicitly set,
	// allowing users to control the enable_thinking parameter.
	// When unset, the parameter is not sent and the API default behavior applies.
	if thinkingEnv := os.Getenv("OBOT_QWEN_MODEL_PROVIDER_ENABLE_THINKING"); thinkingEnv != "" {
		enableThinking := strings.EqualFold(thinkingEnv, "true")
		cfg.CustomPathHandleFuncs = map[string]http.HandlerFunc{
			proxy.ChatCompletionsPath: thinkingMiddleware(enableThinking, &httputil.ReverseProxy{
				Director: newProxyDirector(cfg),
			}),
		}
	}

	if err := proxy.Run(cfg); err != nil {
		panic(err)
	}
}

// normalizeEndpoint trims trailing slashes, parses the URL, infers the scheme,
// and ensures the path ends with /v1.
func normalizeEndpoint(endpoint string) (string, error) {
	endpoint = strings.TrimRight(endpoint, "/")
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}

	if u.Scheme == "" {
		if u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" {
			u.Scheme = "http"
		} else {
			u.Scheme = "https"
		}
	}

	return strings.TrimSuffix(u.String(), "/v1") + "/v1", nil
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
