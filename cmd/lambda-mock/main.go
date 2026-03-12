// lambda-mock simulates the Lambda /auth and /callback endpoints for local development.
// In stateless mode: /auth verifies HMAC on state blob, extracts agent IP,
// and POSTs a fake code directly to the agent's callback endpoint.
//
// Usage (via docker compose or standalone):
//
//	VPN_AUTH_HMAC_SECRET=test-secret
//	LISTEN_ADDR=:8080
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	hmacSecret := mustEnv("VPN_AUTH_HMAC_SECRET")
	addr := getenv("LISTEN_ADDR", ":8080")

	mux := http.NewServeMux()
	mux.HandleFunc("/auth", handleAuth(hmacSecret))

	log.Printf("Lambda mock (stateless) listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server: %v", err)
	}
}

func handleAuth(hmacSecret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		stateBlob := strings.Trim(r.URL.Query().Get("state"), "'")
		if stateBlob == "" {
			http.Error(w, "missing state", http.StatusBadRequest)
			return
		}

		// Verify HMAC on state blob (format: base64payload.mac)
		parts := strings.SplitN(stateBlob, ".", 2)
		if len(parts) != 2 {
			http.Error(w, "invalid state format", http.StatusBadRequest)
			return
		}
		encoded, mac := parts[0], parts[1]

		expectedMAC := sign(hmacSecret, encoded)
		if mac != expectedMAC {
			log.Printf("/auth: invalid HMAC for state")
			http.Error(w, "invalid signature", http.StatusForbidden)
			return
		}

		// Decode payload
		data, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			http.Error(w, "decode state failed", http.StatusBadRequest)
			return
		}

		var payload struct {
			SID string `json:"sid"`
			IP  string `json:"ip"`
			IAT int64  `json:"iat"`
			EXP int64  `json:"exp"`
		}
		if err := json.Unmarshal(data, &payload); err != nil {
			http.Error(w, "unmarshal state failed", http.StatusBadRequest)
			return
		}

		if time.Now().Unix() > payload.EXP {
			http.Error(w, "state expired", http.StatusBadRequest)
			return
		}

		log.Printf("/auth: state OK, sid=%s, agent=%s", payload.SID, payload.IP)

		// POST callback to agent
		callbackReq := map[string]any{
			"code":       "mock-auth-code",
			"session_id": payload.SID,
			"ts":         time.Now().Unix(),
		}
		body, _ := json.Marshal(callbackReq)
		bodyMAC := sign(hmacSecret, string(body))

		agentURL := fmt.Sprintf("http://%s/callback", payload.IP)
		req, err := http.NewRequest(http.MethodPost, agentURL, bytes.NewReader(body))
		if err != nil {
			log.Printf("/auth: build callback request: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Internal-Token", bodyMAC)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Printf("/auth: callback POST failed: %v", err)
			http.Error(w, "callback failed", http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		respBody, _ := io.ReadAll(resp.Body)

		if resp.StatusCode != http.StatusOK {
			log.Printf("/auth: agent returned %d: %s", resp.StatusCode, respBody)
			w.Header().Set("Content-Type", "text/html")
			if resp.StatusCode == http.StatusConflict {
				// 409 — session already processed (double-click or replay).
				w.WriteHeader(http.StatusOK)
				_, _ = fmt.Fprintf(w, `<!DOCTYPE html>
<html><body>
<h1>Already authenticated</h1>
<p>This link has already been used. You can close this window.</p>
</body></html>`)
			} else {
				w.WriteHeader(http.StatusBadGateway)
				_, _ = fmt.Fprintf(w, `<!DOCTYPE html>
<html><body>
<h1>Authentication failed</h1>
<p>Please close this window and reconnect.</p>
</body></html>`)
			}
			return
		}

		log.Printf("/auth: callback accepted for sid=%s", payload.SID)
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprintf(w, `<!DOCTYPE html>
<html><body>
<h1>Authentication successful</h1>
<p>You can close this window and return to your VPN client.</p>
</body></html>`)
	}
}

func sign(secret, data string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("required env var %s is not set", key)
	}
	return v
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
