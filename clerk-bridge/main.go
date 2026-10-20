// Command clerk-bridge lets Keycloak look up Clerk users and check their passwords
// without Keycloak ever holding the Clerk secret key.
package main

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
)

func main() {
	clerk := NewClerk(envOr("CLERK_API_URL", "https://api.clerk.com/v1"), mustEnv("CLERK_SECRET_KEY"))
	handler := NewHandler(clerk, mustEnv("CLERK_BRIDGE_TOKEN"))
	addr := ":" + envOr("PORT", "8090")
	log.Printf("clerk-bridge listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, handler))
}

// NewHandler serves the bridge API. Every route except /healthz needs the shared bearer token.
func NewHandler(clerk *Clerk, token string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("GET /users/lookup", func(w http.ResponseWriter, r *http.Request) {
		identifier := strings.TrimSpace(r.URL.Query().Get("identifier"))
		if identifier == "" {
			http.Error(w, "identifier is required", http.StatusBadRequest)
			return
		}
		user, err := clerk.FindByIdentifier(r.Context(), identifier)
		writeUser(w, user, err)
	})

	mux.HandleFunc("GET /users/{id}", func(w http.ResponseWriter, r *http.Request) {
		user, err := clerk.Get(r.Context(), r.PathValue("id"))
		writeUser(w, user, err)
	})

	mux.HandleFunc("POST /users/{id}/verify-password", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Password == "" {
			http.Error(w, "password is required", http.StatusBadRequest)
			return
		}
		verified, err := clerk.VerifyPassword(r.Context(), r.PathValue("id"), body.Password)
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, map[string]bool{"verified": verified})
	})

	return logRequests(requireToken(token, mux))
}

// statusRecorder captures the response status for the access log.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// logRequests logs method, path and status only. Bodies carry passwords and are never logged.
func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		if r.URL.Path != "/healthz" {
			log.Printf("%s %s -> %d", r.Method, r.URL.Path, rec.status)
		}
	})
}

func requireToken(token string, next http.Handler) http.Handler {
	want := []byte("Bearer " + token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" && subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), want) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeUser(w http.ResponseWriter, user User, err error) {
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, user)
}

func writeError(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrNotFound) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	log.Printf("clerk error: %v", err)
	http.Error(w, "clerk unavailable", http.StatusBadGateway)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("%s is required", key)
	}
	return v
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
