package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrNotFound means Clerk has no such user.
var ErrNotFound = errors.New("clerk: user not found")

// User is the slice of a Clerk user that Keycloak needs.
type User struct {
	ID              string `json:"id"`
	Username        string `json:"username"`
	Email           string `json:"email"`
	EmailVerified   bool   `json:"emailVerified"`
	FirstName       string `json:"firstName"`
	LastName        string `json:"lastName"`
	PasswordEnabled bool   `json:"passwordEnabled"`
}

// Clerk talks to the Clerk Backend API with the instance secret key.
type Clerk struct {
	baseURL   string
	secretKey string
	http      *http.Client
}

func NewClerk(baseURL, secretKey string) *Clerk {
	return &Clerk{
		baseURL:   strings.TrimRight(baseURL, "/"),
		secretKey: secretKey,
		http:      &http.Client{Timeout: 10 * time.Second},
	}
}

type clerkUser struct {
	ID                    string  `json:"id"`
	Username              *string `json:"username"`
	FirstName             *string `json:"first_name"`
	LastName              *string `json:"last_name"`
	PasswordEnabled       bool    `json:"password_enabled"`
	PrimaryEmailAddressID *string `json:"primary_email_address_id"`
	EmailAddresses        []struct {
		ID           string `json:"id"`
		EmailAddress string `json:"email_address"`
		Verification *struct {
			Status string `json:"status"`
		} `json:"verification"`
	} `json:"email_addresses"`
}

func (u clerkUser) toUser() User {
	out := User{
		ID:              u.ID,
		Username:        deref(u.Username),
		FirstName:       deref(u.FirstName),
		LastName:        deref(u.LastName),
		PasswordEnabled: u.PasswordEnabled,
	}
	for _, e := range u.EmailAddresses {
		if u.PrimaryEmailAddressID != nil && e.ID == *u.PrimaryEmailAddressID {
			out.Email = e.EmailAddress
			out.EmailVerified = e.Verification != nil && e.Verification.Status == "verified"
		}
	}
	return out
}

// FindByIdentifier looks a user up by email (when the identifier contains "@") or username.
func (c *Clerk) FindByIdentifier(ctx context.Context, identifier string) (User, error) {
	q := url.Values{}
	if strings.Contains(identifier, "@") {
		q.Set("email_address", identifier)
	} else {
		q.Set("username", identifier)
	}
	var users []clerkUser
	if _, err := c.do(ctx, http.MethodGet, "/users?"+q.Encode(), nil, &users); err != nil {
		return User{}, err
	}
	if len(users) == 0 {
		return User{}, ErrNotFound
	}
	return users[0].toUser(), nil
}

func (c *Clerk) Get(ctx context.Context, id string) (User, error) {
	var u clerkUser
	status, err := c.do(ctx, http.MethodGet, "/users/"+url.PathEscape(id), nil, &u)
	if status == http.StatusNotFound {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}
	return u.toUser(), nil
}

// VerifyPassword returns false for a wrong password; Clerk answers that with 422 incorrect_password.
func (c *Clerk) VerifyPassword(ctx context.Context, id, password string) (bool, error) {
	var res struct {
		Verified bool `json:"verified"`
	}
	status, err := c.do(ctx, http.MethodPost, "/users/"+url.PathEscape(id)+"/verify_password",
		map[string]string{"password": password}, &res)
	switch {
	case status == http.StatusNotFound:
		return false, ErrNotFound
	case status == http.StatusUnprocessableEntity || status == http.StatusBadRequest:
		return false, nil
	case err != nil:
		return false, err
	}
	return res.Verified, nil
}

// do returns the HTTP status alongside any error so callers can map Clerk's error statuses.
func (c *Clerk) do(ctx context.Context, method, path string, body, out any) (int, error) {
	var reader io.Reader = http.NoBody
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.secretKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("clerk: %s %s: HTTP %d", method, path, resp.StatusCode)
	}
	return resp.StatusCode, json.NewDecoder(resp.Body).Decode(out)
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
