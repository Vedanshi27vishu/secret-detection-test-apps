package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

// ============================================================
// INTENTIONALLY HARDCODED SECRETS — for secret detection testing
// ============================================================

// SECRET: MySQL DSN hardcoded as a constant — detection target
// Format: username:password@tcp(host:port)/dbname
const dbConnString = "mysql_admin:MySQLSecret@2024!@tcp(localhost:3306)/appdb"

// SECRET: Internal service API key hardcoded — detection target
const internalAPIKey = "api_key_3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f"

// SECRET: Bearer token for upstream service — detection target
const upstreamBearerToken = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJteXNxbC1zZXJ2aWNlIiwiaWF0IjoxNjAwMDAwMDAwfQ.mysqlFakeSignatureForTestingOnly"

// SECRET: Custom auth token used in X-Custom-Auth header — detection target
const customAuthToken = "custom_auth_mYsQlT0k3n_X9z7w5v3u1s"

// fakeUpstreamURL simulates an upstream service endpoint
const fakeUpstreamURL = "https://internal.example.com/api/verify"

// User represents a row returned from the users table
type User struct {
	ID        int    `json:"id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	CreatedAt string `json:"created_at"`
}

// LoginRequest is the expected POST body for /login
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"` // SECRET: password field in request body
	Token    string `json:"token"`    // SECRET: token field in request body
}

// LoginResponse is the JSON returned on successful login
type LoginResponse struct {
	Message     string `json:"message"`
	SessionID   string `json:"session_id"`   // SECRET: session token in response
	AccessToken string `json:"access_token"` // SECRET: access token in response
	DBSource    string `json:"db_source"`    // SECRET: leaks DSN in response — detection target
}

func main() {
	// SECRET: log the MySQL DSN at startup — simulates a common accidental log leak
	log.Printf("[DB] Connecting with DSN: %s", dbConnString)

	// SECRET: log API key and auth token at startup — detection targets
	log.Printf("[startup] Using API key: %s", internalAPIKey)
	log.Printf("[startup] Using upstream token: %s", upstreamBearerToken)

	mux := http.NewServeMux()
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/users", usersHandler)

	log.Println("[server] mysql-app listening on :8082")
	if err := http.ListenAndServe(":8082", mux); err != nil {
		log.Fatalf("[server] failed to start: %v", err)
	}
}

// loginHandler handles POST /login
// Secrets present:
//   - Request body: password, token
//   - Incoming headers: Authorization, X-Api-Key, X-Custom-Auth (read and logged)
//   - Incoming cookie: session_id (read and logged)
//   - Response body: session_id, access_token, db_source (DSN)
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read and parse request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var req LoginRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	// SECRET: log credentials from request body — simulates accidental credential logging
	log.Printf("[login] Attempt — username=%s password=%s token=%s",
		req.Username, req.Password, req.Token)

	// SECRET: read and log Authorization header — detection target
	authHeader := r.Header.Get("Authorization")
	// SECRET: read and log X-Api-Key header — detection target
	apiKeyHeader := r.Header.Get("X-Api-Key")
	// SECRET: read and log X-Custom-Auth header — detection target
	customAuthHeader := r.Header.Get("X-Custom-Auth")

	log.Printf("[login] Incoming headers — Authorization=%s X-Api-Key=%s X-Custom-Auth=%s",
		authHeader, apiKeyHeader, customAuthHeader)

	// SECRET: read and log session_id cookie — detection target
	cookie, err := r.Cookie("session_id")
	if err == nil {
		log.Printf("[login] session_id cookie: %s", cookie.Value)
	}

	// Simulate calling upstream service with hardcoded secrets in headers
	callUpstreamService()

	// SECRET: session_id, access_token and db_source (DSN) in response body — detection targets
	resp := LoginResponse{
		Message:     fmt.Sprintf("welcome, %s", req.Username),
		SessionID:   "sess_mysql_7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c", // SECRET: hardcoded session ID
		AccessToken: "tok_mysql_aBcDeFgHiJkLmNoPqRsTuVwXyZ9876543",  // SECRET: hardcoded access token
		DBSource:    dbConnString,                                     // SECRET: intentional DSN leak in response
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// usersHandler handles GET /users
// Secrets present:
//   - Incoming query params: api_key, session_id
//   - Incoming headers: Authorization, X-Api-Key, X-Custom-Auth
//   - Response body: db_source (DSN), users list
func usersHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// SECRET: api_key and session_id in URL query params — detection targets
	apiKey := r.URL.Query().Get("api_key")
	sessionID := r.URL.Query().Get("session_id")

	log.Printf("[users] Query params — api_key=%s session_id=%s", apiKey, sessionID)

	// SECRET: Authorization, X-Api-Key, and X-Custom-Auth headers — detection targets
	authHeader := r.Header.Get("Authorization")
	apiKeyHeader := r.Header.Get("X-Api-Key")
	customAuthHeader := r.Header.Get("X-Custom-Auth")

	log.Printf("[users] Incoming headers — Authorization=%s X-Api-Key=%s X-Custom-Auth=%s",
		authHeader, apiKeyHeader, customAuthHeader)

	// Simulate fetching rows from MySQL users table
	// In production this would use dbConnString with a real *sql.DB
	users := simulateDBQuery()

	type Response struct {
		DBSource string `json:"db_source"` // SECRET: full MySQL DSN leaked in response — detection target
		Count    int    `json:"count"`
		Users    []User `json:"users"`
	}

	// SECRET: db_source in response leaks the full MySQL connection string
	resp := Response{
		DBSource: dbConnString, // intentional leak for detection testing
		Count:    len(users),
		Users:    users,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// callUpstreamService simulates an outgoing HTTP call to an internal service.
// Secrets present:
//   - Authorization header: hardcoded Bearer token
//   - X-Api-Key header: hardcoded API key
func callUpstreamService() {
	client := &http.Client{Timeout: 5 * time.Second}

	req, err := http.NewRequest(http.MethodGet, fakeUpstreamURL, nil)
	if err != nil {
		log.Printf("[upstream] failed to build request: %v", err)
		return
	}

	// SECRET: hardcoded Bearer token in outgoing Authorization header — detection target
	req.Header.Set("Authorization", upstreamBearerToken)
	// SECRET: hardcoded API key in outgoing X-Api-Key header — detection target
	req.Header.Set("X-Api-Key", internalAPIKey)

	log.Printf("[upstream] Calling %s with Authorization=%s X-Api-Key=%s",
		fakeUpstreamURL, upstreamBearerToken, internalAPIKey)

	resp, err := client.Do(req)
	if err != nil {
		// Expected — fakeUpstreamURL doesn't exist; log and continue
		log.Printf("[upstream] request failed (expected in test env): %v", err)
		return
	}
	defer resp.Body.Close()
	log.Printf("[upstream] response status: %s", resp.Status)
}

// simulateDBQuery returns hardcoded users as if they were fetched from MySQL.
func simulateDBQuery() []User {
	return []User{
		{ID: 1, Username: "alice", Email: "alice@example.com", CreatedAt: "2024-01-15T10:00:00Z"},
		{ID: 2, Username: "bob", Email: "bob@example.com", CreatedAt: "2024-02-20T14:30:00Z"},
		{ID: 3, Username: "carol", Email: "carol@example.com", CreatedAt: "2024-03-05T09:15:00Z"},
	}
}
