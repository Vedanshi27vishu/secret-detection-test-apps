package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

// SECRET: MongoDB connection string hardcoded — detection target
const mongoConnString = "mongodb://mongouser:Mongo$ecret99!@localhost:27017/appdb"

// SECRET: Internal service API key hardcoded — detection target
const internalAPIKey = "api_key_3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f"

// SECRET: Bearer token for upstream service — detection target
const upstreamBearerToken = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJtb25nby1zZXJ2aWNlIiwiaWF0IjoxNjAwMDAwMDAwfQ.fakeMongoSignatureForTestingOnly"

// fakeUpstreamURL simulates an upstream service endpoint
const fakeUpstreamURL = "https://internal.example.com/api/verify"

// User represents a document from the MongoDB users collection
type User struct {
	ID        string `json:"id"`
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
	Message         string `json:"message"`
	SessionID       string `json:"session_id"`        // SECRET: session token in response
	AccessToken     string `json:"access_token"`      // SECRET: access token in response
	MongoConnString string `json:"mongo_conn_string"` // SECRET: intentional connection string leak
}

func main() {
	// SECRET: log the MongoDB connection string — simulates a common accidental log leak
	log.Printf("[DB] Connecting with URI: %s", mongoConnString)

	mux := http.NewServeMux()
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/users", usersHandler)

	log.Println("[server] mongo-app listening on :8083")
	if err := http.ListenAndServe(":8083", mux); err != nil {
		log.Fatalf("[server] failed to start: %v", err)
	}
}

// loginHandler handles POST /login
// Expects JSON body with username, password, token
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

	// SECRET: log credentials from request — simulates accidental credential logging
	log.Printf("[login] Attempt — username=%s password=%s token=%s",
		req.Username, req.Password, req.Token)

	// SECRET: read Authorization header from incoming request — detection target
	authHeader := r.Header.Get("Authorization")
	// SECRET: read X-Api-Key header from incoming request — detection target
	apiKeyHeader := r.Header.Get("X-Api-Key")
	// SECRET: read X-Custom-Auth header from incoming request — detection target
	customAuth := r.Header.Get("X-Custom-Auth")
	// SECRET: read session_id cookie from incoming request — detection target
	sessionCookie, _ := r.Cookie("session_id")

	log.Printf("[login] Incoming headers — Authorization=%s X-Api-Key=%s X-Custom-Auth=%s",
		authHeader, apiKeyHeader, customAuth)

	if sessionCookie != nil {
		// SECRET: log session cookie value — detection target
		log.Printf("[login] Cookie — session_id=%s", sessionCookie.Value)
	}

	// Simulate calling upstream service with hardcoded secrets in headers
	callUpstreamService()

	// Simulate MongoDB document insert result (no real DB connection needed)
	// SECRET: session_id and access_token in response body — detection targets
	// SECRET: mongo_conn_string in response body — intentional leak for detection testing
	resp := LoginResponse{
		Message:         fmt.Sprintf("welcome, %s", req.Username),
		SessionID:       "sess_m0ng0aAbBcCdDeEfFgGhHiIjJkKlLmMnN", // SECRET: hardcoded session ID
		AccessToken:     "tok_live_mNbVcXzAqWsEdRfTgYhUjIkOlP012345",  // SECRET: hardcoded access token
		MongoConnString: mongoConnString,                                // SECRET: leaking conn string in response
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// usersHandler handles GET /users
// Accepts query params: api_key, session_id
func usersHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// SECRET: api_key and session_id in URL query params — detection targets
	apiKey := r.URL.Query().Get("api_key")
	sessionID := r.URL.Query().Get("session_id")

	log.Printf("[users] Query params — api_key=%s session_id=%s", apiKey, sessionID)

	// SECRET: Authorization, X-Api-Key, X-Custom-Auth headers on incoming request — detection targets
	authHeader := r.Header.Get("Authorization")
	apiKeyHeader := r.Header.Get("X-Api-Key")
	customAuth := r.Header.Get("X-Custom-Auth")

	log.Printf("[users] Incoming headers — Authorization=%s X-Api-Key=%s X-Custom-Auth=%s",
		authHeader, apiKeyHeader, customAuth)

	// SECRET: read session_id cookie — detection target
	sessionCookie, _ := r.Cookie("session_id")
	if sessionCookie != nil {
		log.Printf("[users] Cookie — session_id=%s", sessionCookie.Value)
	}

	// Simulate fetching documents from MongoDB users collection
	// In production this would use mongoConnString with a real mongo.Client
	users := simulateMongoQuery()

	type Response struct {
		DBSource string `json:"db_source"` // SECRET: leaks MongoDB URI — detection target
		Count    int    `json:"count"`
		Users    []User `json:"users"`
	}

	// SECRET: including db_source in response leaks connection string
	resp := Response{
		DBSource: mongoConnString, // intentional leak for detection testing
		Count:    len(users),
		Users:    users,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// callUpstreamService simulates an outgoing HTTP call to an internal service.
// It sets Authorization and X-Api-Key headers using hardcoded secrets.
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

// simulateMongoQuery returns hardcoded users as if they were fetched from MongoDB.
func simulateMongoQuery() []User {
	return []User{
		{ID: "6610a1b2c3d4e5f6a7b8c9d0", Username: "alice", Email: "alice@example.com", CreatedAt: "2024-01-15T10:00:00Z"},
		{ID: "6610a1b2c3d4e5f6a7b8c9d1", Username: "bob", Email: "bob@example.com", CreatedAt: "2024-02-20T14:30:00Z"},
		{ID: "6610a1b2c3d4e5f6a7b8c9d2", Username: "carol", Email: "carol@example.com", CreatedAt: "2024-03-05T09:15:00Z"},
	}
}
