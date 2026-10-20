package main

import (
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeClerk mimics the Clerk Backend API responses the bridge relies on.
// The accepted password is random per run, so no credential-like literal lives in the repo.
func fakeClerk(t *testing.T, acceptedPassword string) *httptest.Server {
	t.Helper()
	user := `{"id":"user_1","username":"jane","first_name":"Jane","last_name":null,"password_enabled":true,
		"primary_email_address_id":"idn_1","email_addresses":[
		{"id":"idn_2","email_address":"old@example.com","verification":{"status":"verified"}},
		{"id":"idn_1","email_address":"jane@example.com","verification":{"status":"verified"}}]}`
	mux := http.NewServeMux()
	mux.HandleFunc("GET /users", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("username") == "jane" || r.URL.Query().Get("email_address") == "jane@example.com" {
			w.Write([]byte("[" + user + "]"))
			return
		}
		w.Write([]byte("[]"))
	})
	mux.HandleFunc("GET /users/{id}", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("id") != "user_1" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Write([]byte(user))
	})
	mux.HandleFunc("POST /users/{id}/verify_password", func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Password string }
		json.NewDecoder(r.Body).Decode(&body)
		if body.Password != acceptedPassword {
			w.WriteHeader(http.StatusUnprocessableEntity)
			w.Write([]byte(`{"errors":[{"code":"incorrect_password"}]}`))
			return
		}
		w.Write([]byte(`{"verified":true}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func call(t *testing.T, h http.Handler, method, path, body, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func passwordBody(p string) string {
	b, _ := json.Marshal(map[string]string{"password": p})
	return string(b)
}

func TestBridge(t *testing.T) {
	bearer, accepted := rand.Text(), rand.Text()
	h := NewHandler(NewClerk(fakeClerk(t, accepted).URL, rand.Text()), bearer)

	tests := []struct {
		name, method, path, body, bearer string
		wantStatus                       int
		wantBody                         string
	}{
		{"health needs no bearer", "GET", "/healthz", "", "", 204, ""},
		{"missing bearer", "GET", "/users/lookup?identifier=jane", "", "", 401, ""},
		{"wrong bearer", "GET", "/users/lookup?identifier=jane", "", rand.Text(), 401, ""},
		{"lookup by username", "GET", "/users/lookup?identifier=jane", "", bearer, 200, `"email":"jane@example.com"`},
		{"lookup by email", "GET", "/users/lookup?identifier=jane@example.com", "", bearer, 200, `"id":"user_1"`},
		{"lookup unknown", "GET", "/users/lookup?identifier=ghost", "", bearer, 404, ""},
		{"get by id", "GET", "/users/user_1", "", bearer, 200, `"firstName":"Jane"`},
		{"get unknown id", "GET", "/users/user_x", "", bearer, 404, ""},
		{"accepted password", "POST", "/users/user_1/verify-password", passwordBody(accepted), bearer, 200, `{"verified":true}`},
		{"rejected password", "POST", "/users/user_1/verify-password", passwordBody(rand.Text()), bearer, 200, `{"verified":false}`},
		{"empty password", "POST", "/users/user_1/verify-password", `{}`, bearer, 400, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := call(t, h, tt.method, tt.path, tt.body, tt.bearer)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body %q)", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tt.wantBody) {
				t.Fatalf("body = %q, want it to contain %q", rec.Body.String(), tt.wantBody)
			}
		})
	}
}
