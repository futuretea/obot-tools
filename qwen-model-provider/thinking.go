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
// into the "chat_template_kwargs" object of the JSON request body for chat completion requests,
// then delegates to the next handler.
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

		// Get or create chat_template_kwargs object
		var chatTemplateKwargs map[string]any
		if existing, exists := reqBody["chat_template_kwargs"]; exists {
			if existingMap, ok := existing.(map[string]any); ok {
				chatTemplateKwargs = existingMap
			} else {
				chatTemplateKwargs = make(map[string]any)
			}
		} else {
			chatTemplateKwargs = make(map[string]any)
		}

		// Only inject enable_thinking if not already set by the caller
		if _, exists := chatTemplateKwargs["enable_thinking"]; !exists {
			chatTemplateKwargs["enable_thinking"] = enableThinking
		}

		// Update the request body with the modified chat_template_kwargs
		reqBody["chat_template_kwargs"] = chatTemplateKwargs

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
