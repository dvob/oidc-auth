package oidcproxy

import (
	"time"

	"golang.org/x/oauth2"
)

// Session represents a session which usually gets stored encrypted in a
// cookie. A session is initialized based on a set of tokens from a provider
// (TokenResponse) in a SetupSessionFunc.
type Session struct {
	ProviderID string `json:"provider_id"`

	// Expiry specifies the time when the session expires. This is set
	// during the session setup and is usually obtained from the field
	// expires_in from the Access Token Response (see
	// https://datatracker.ietf.org/doc/html/rfc6749#section-5.1).
	Expiry time.Time `json:"expiry"`

	// Tokens usually stores the issued tokens from which the session got
	// created. If you don't need the tokens you can remove them during the
	// session setup which helps to keep the cookie small.
	Tokens *Tokens `json:"tokens,omitempty"`

	// User represents the authenticated user. The user can be initialized
	// during the session setup. Usually for this values from the claims in
	// the id_token are used.
	User *User `json:"user,omitempty"`
}

type Tokens struct {
	oauth2.Token
	IDToken string `json:"id_token"`
}

type User struct {
	ID     string   `json:"id"`
	Name   string   `json:"name"`
	Groups []string `json:"groups,omitempty"`
	Extra  any      `json:"extra,omitempty"`
}

func (s *Session) Valid() bool {
	if s == nil {
		return false
	}
	return s.Expiry.After(time.Now())
}

func (s *Session) HasAccessToken() bool {
	if s == nil {
		return false
	}
	if s.Tokens == nil {
		return false
	}
	return s.Tokens.AccessToken != ""
}

func (s *Session) HasRefreshToken() bool {
	if s == nil {
		return false
	}
	if s.Tokens == nil {
		return false
	}
	return s.Tokens.RefreshToken != ""
}

func (s *Session) HasIDToken() bool {
	if s == nil {
		return false
	}
	if s.Tokens == nil {
		return false
	}
	return s.Tokens.IDToken != ""
}

func (s *Session) AccessToken() string {
	if !s.HasAccessToken() {
		return ""
	}
	return s.Tokens.AccessToken
}

func (s *Session) RefreshToken() string {
	if !s.HasRefreshToken() {
		return ""
	}
	return s.Tokens.RefreshToken
}

func (s *Session) IDToken() string {
	if !s.HasIDToken() {
		return ""
	}
	return s.Tokens.IDToken
}
