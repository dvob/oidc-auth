package oidcauth

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// SessionSetupFunc is used to setup a new session. This happens always after a
// IDP issues a new set of tokens. This is either on the initial login where we
// get a set of tokens using an authorization code or if we obtain a new set of
// tokens using a refresh_token.
// It turns the returend tokens into a session. This allows to customize the
// session setup based on the tokens. For example obtaining additional
// information like groups from other sources (e.g. userinfo endpoint) or
// setting a custom expiration time. Be aware that on a refresh not every
// provider does return a new id_token. If you return an error no new session
// will be established.
// Consider returning ServerErr to control what HTTP status code is retuned and
// what error is shown to the user.
type SessionSetupFunc func(ctx context.Context, p *Provider, t *TokenResponse, s *Session) error

type TokenResponse struct {
	// Token contains the standard OAuth2 tokens like the access_token.
	oauth2.Token

	// RawIDToken contains the id_token if it was available in the
	// response.
	RawIDToken string

	// IDToken contains the parsed and validated id_token if it was
	// available in the response.
	IDToken *oidc.IDToken
}

var defaultSessionSetupFunc SessionSetupFunc = func(ctx context.Context, p *Provider, t *TokenResponse, s *Session) error {
	const defaultSessionDuration = time.Minute * 15

	s.Tokens = &Tokens{
		Token:   t.Token,
		IDToken: t.RawIDToken,
	}

	// Set expiry of the session according to the expires_in field in the
	// token response. See https://datatracker.ietf.org/doc/html/rfc6749#section-4.2.2
	// This field is not REQUIRED so we set a default if it is not available.
	if t.Token.Expiry.IsZero() {
		s.Expiry = time.Now().Add(defaultSessionDuration)
	} else {
		// use the expires_in from the token response
		s.Expiry = t.Token.Expiry
	}

	if t.IDToken == nil {
		return nil
	}

	// If an id_token is available try to obtain a user id and username
	// from the id_token. To use your own logic implement your own
	// SessionSetupFunc to overwrite theses values.
	claims := struct {
		EMail             string `json:"email"`
		PreferredUsername string `json:"preferred_username"`
	}{}

	_ = t.IDToken.Claims(&claims)

	s.User = &User{
		ID:   t.IDToken.Subject,
		Name: claims.EMail,
	}
	if s.User.Name == "" {
		s.User.Name = claims.PreferredUsername
	}

	return nil
}

// ChainSessionSetupFunc chains multiple sessionSetupFuncs. If one function
// returns an error subsequent functions are not called.
func ChainSessionSetupFunc(sessionSetupFuncs ...SessionSetupFunc) SessionSetupFunc {
	return func(ctx context.Context, provider *Provider, tr *TokenResponse, s *Session) error {
		for _, sessionSetupFunc := range sessionSetupFuncs {
			err := sessionSetupFunc(ctx, provider, tr, s)
			if err != nil {
				return err
			}
		}
		return nil
	}
}

// SaveGroups adds groups from id_token claims to session. It ignores errors.
func SaveGroups() SessionSetupFunc {
	return func(ctx context.Context, p *Provider, t *TokenResponse, s *Session) error {
		if t.IDToken == nil {
			return nil
		}

		claims := struct {
			Groups []string `json:"groups"`
		}{}

		err := t.IDToken.Claims(&claims)
		if err != nil {
			return nil
		}

		if s.User != nil {
			s.User.Groups = claims.Groups
		} else {
			s.User = &User{
				Groups: claims.Groups,
			}
		}
		return nil
	}
}

// RequireIDTokenGroup verifies that at least one of the given groups is
// available in the id_token.
func RequireIDTokenGroup(groups ...string) SessionSetupFunc {
	return func(ctx context.Context, p *Provider, t *TokenResponse, s *Session) error {
		if t.IDToken == nil {
			return fmt.Errorf("id token missing to check groups")
		}

		claims := struct {
			Groups []string `json:"groups"`
		}{}

		err := t.IDToken.Claims(&claims)
		if err != nil {
			return err
		}

		for _, group := range groups {
			if slices.Contains(claims.Groups, group) {
				return nil
			}
		}
		return ErrDirect(http.StatusUnauthorized, fmt.Errorf("you are not authorized. you need to be a member of one of theses groups: %s", strings.Join(groups, ", ")))
	}
}

type ClaimCheckFunc func(claims map[string]any) error

func NewSessionClaimCheckFunc(claimCheckFunc ClaimCheckFunc) SessionSetupFunc {
	return func(ctx context.Context, provider *Provider, tr *TokenResponse, s *Session) error {
		if tr.IDToken == nil {
			return claimCheckFunc(nil)
		}

		claims := map[string]any{}
		err := tr.IDToken.Claims(&claims)
		if err != nil {
			return err
		}
		err = claimCheckFunc(claims)
		if err != nil {
			return ErrDirect(http.StatusUnauthorized, err)
		}
		return nil
	}
}
