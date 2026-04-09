package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
)

// ============================================================
// INTENTIONALLY HARDCODED SECRETS — for secret detection testing
// ============================================================

// SECRET: JWT token hardcoded as a constant.
// Format: <header>.<payload>.<signature> (realistic HS256 token)
const hardcodedJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzEyMyIsIm5hbWUiOiJKb2huIERvZSIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjoxNzAwMDg2NDAwfQ.4Gdnl5BPBqAXbKFwmGp9V8fLqcW2vRjYkZo3nTsE1HM"

// SECRET: API key hardcoded as a constant.
const hardcodedAPIKey = "sk-live-aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abcd"

// SECRET: Shared client secret used in OAuth-style flows.
const clientSecret = "cs_prod_XyZ9876aBcDeFgHiJkLmNoPqRsTuV54321"

// SECRET: Session ID used as a cookie value.
const sessionID = "sess_abc123XYZprod9876"

// SECRET: Upstream service URL with embedded API key in query param.
// The api_key query param is a secret that should be detected in URLs.
const upstreamURL = "https://internal-profile-api.example.com/user?api_key=sk-upstream-SECRET99887766aabbccdd&session_id=sess_abc123XYZprod9876"

// ============================================================
// Request / Response types
// ============================================================

type LoginRequest struct {
	Username     string `json:"username"`
	Password     string `json:"password"`       // SECRET: password in request body
	ClientSecret string `json:"client_secret"`  // SECRET: OAuth client_secret in body
	Token        string `json:"token"`           // SECRET: token field in body
}

type LoginResponse struct {
	AccessToken string `json:"access_token"` // SECRET: JWT returned in response body
	TokenType   string `json:"token_type"`
	UserID      string `json:"user_id"`
}

type ProfileResponse struct {
	UserID           string          `json:"user_id"`
	Name             string          `json:"name"`
	Email            string          `json:"email"`
	UpstreamResponse json.RawMessage `json:"upstream_response"`
}

// ============================================================
// Handlers
// ============================================================

// loginHandler handles POST /login
// Secrets present:
//   - Request body: password, client_secret, token
//   - Response body: access_token (JWT)
//   - Incoming headers: Authorization, X-Api-Key, Cookie (read and logged)
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// SECRET: read and log incoming Authorization header (Bearer JWT)
	authHeader := r.Header.Get("Authorization")
	log.Printf("[login] Authorization header: %s", authHeader)

	// SECRET: read and log incoming API key header
	apiKey := r.Header.Get("X-Api-Key")
	log.Printf("[login] X-Api-Key header: %s", apiKey)

	// SECRET: read and log session cookie
	cookie, err := r.Cookie("session_id")
	if err == nil {
		log.Printf("[login] session_id cookie: %s", cookie.Value)
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	// SECRET: password, client_secret, and token are logged (detection target)
	log.Printf("[login] username=%s password=%s client_secret=%s token=%s",
		req.Username, req.Password, req.ClientSecret, req.Token)

	// Simulate credential validation (always succeeds in test app)
	resp := LoginResponse{
		AccessToken: hardcodedJWT, // SECRET: JWT in response body
		TokenType:   "Bearer",
		UserID:      "user_123",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// profileHandler handles GET /profile
// Secrets present:
//   - Outgoing request: Authorization header (JWT), X-Api-Key header, api_key + session_id in URL query
//   - Incoming headers: Authorization, X-Api-Key, Cookie (forwarded upstream)
//   - Response body: upstream_response (may contain secrets from upstream)
func profileHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// SECRET: read Authorization header from incoming request
	incomingAuth := r.Header.Get("Authorization")
	log.Printf("[profile] incoming Authorization: %s", incomingAuth)

	// SECRET: api_key and session_id from incoming query params (detection targets)
	queryAPIKey := r.URL.Query().Get("api_key")
	querySession := r.URL.Query().Get("session_id")
	log.Printf("[profile] query api_key=%s session_id=%s", queryAPIKey, querySession)

	// Make outgoing HTTP request to upstream service
	// SECRET: upstreamURL contains api_key and session_id in query string
	// SECRET: Authorization header carries the hardcoded JWT
	// SECRET: X-Api-Key header carries the hardcoded API key
	upstreamResp, err := callUpstream()
	if err != nil {
		log.Printf("[profile] upstream error: %v", err)
		upstreamResp = json.RawMessage(`{"error":"upstream unavailable"}`)
	}

	profile := ProfileResponse{
		UserID:           "user_123",
		Name:             "John Doe",
		Email:            "john.doe@example.com",
		UpstreamResponse: upstreamResp,
	}

	w.Header().Set("Content-Type", "application/json")
	// SECRET: set outgoing cookie header with session_id
	w.Header().Set("Set-Cookie", fmt.Sprintf("session_id=%s; HttpOnly", sessionID))
	json.NewEncoder(w).Encode(profile)
}

// callUpstream makes an authenticated HTTP request to an internal service.
// Secrets present:
//   - URL query params: api_key, session_id  (from upstreamURL constant)
//   - Authorization header: Bearer <JWT>
//   - X-Api-Key header: API key
func callUpstream() (json.RawMessage, error) {
	client := &http.Client{}

	req, err := http.NewRequest(http.MethodGet, upstreamURL, nil)
	if err != nil {
		return nil, err
	}

	// SECRET: hardcoded JWT added to outgoing Authorization header
	req.Header.Set("Authorization", "Bearer "+hardcodedJWT)

	// SECRET: hardcoded API key added to outgoing X-Api-Key header
	req.Header.Set("X-Api-Key", hardcodedAPIKey)

	// SECRET: session cookie added to outgoing Cookie header
	req.Header.Set("Cookie", "session_id="+sessionID)

	resp, err := client.Do(req)
	if err != nil {
		// Return a mock response so the app works offline
		mock := map[string]string{
			"status":  "ok",
			"user_id": "user_123",
			"note":    "mock upstream response (real call failed)",
		}
		b, _ := json.Marshal(mock)
		return b, nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

// ============================================================
// Main
// ============================================================

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/profile", profileHandler)

	// Health check — no secrets
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"status":"ok"}`)
	})

	addr := ":8080"
	log.Printf("http-auth-app listening on %s", addr)

	// SECRET: startup log prints the API key and JWT for "debugging"
	// This is a realistic mistake developers make — another detection target.
	log.Printf("Using API key: %s", hardcodedAPIKey)
	log.Printf("Using JWT: %s", strings.TrimRight(hardcodedJWT, "="))

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
