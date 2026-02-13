package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
)

// thinkingMiddleware returns an http.HandlerFunc that injects the "enable_thinking" field
// into the JSON request body of chat completion requests, then delegates to the next handler.
func thinkingMiddleware(enableThinking bool, next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to read request body: %v", err), http.StatusBadRequest)
			return
		}
		_ = r.Body.Close()

		var reqBody map[string]any
		if err := json.Unmarshal(body, &reqBody); err != nil {
			// If body is not valid JSON, forward as-is
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.ContentLength = int64(len(body))
			next.ServeHTTP(w, r)
			return
		}

		// Only inject enable_thinking if not already set by the caller
		if _, exists := reqBody["enable_thinking"]; !exists {
			reqBody["enable_thinking"] = enableThinking
		}

		modified, err := json.Marshal(reqBody)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to marshal request body: %v", err), http.StatusInternalServerError)
			return
		}

		r.Body = io.NopCloser(bytes.NewReader(modified))
		r.ContentLength = int64(len(modified))
		r.Header.Set("Content-Length", strconv.Itoa(len(modified)))

		next.ServeHTTP(w, r)
	}
}
