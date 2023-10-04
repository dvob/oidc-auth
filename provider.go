package oidcproxy

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type ProviderConfig struct {
	Identifier             string     `json:"identifier,omitempty"`
	Name                   string     `json:"name"`
	IssuerURL              string     `json:"issuer_url"`
	ClientID               string     `json:"client_id"`
	ClientSecret           string     `json:"client_secret"`
	Scopes                 []string   `json:"scopes"`
	AuthorizationParameter url.Values `json:"authorization_parameters"`
	TokenParameters        url.Values `json:"token_parameters"`
	CallbackURL            string     `json:"callback_url"`
	Endpoints
}

type Endpoints struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	IntrospectionEndpoint string `json:"introspection_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
	RevocationEndpoint    string `json:"revocation_endpoint"`
}

// Merge sets e to e2 if e is not set
func (e *Endpoints) Merge(e2 *Endpoints) {
	if e.AuthorizationEndpoint == "" {
		e.AuthorizationEndpoint = e2.AuthorizationEndpoint
	}
	if e.TokenEndpoint == "" {
		e.TokenEndpoint = e2.TokenEndpoint
	}
	if e.IntrospectionEndpoint == "" {
		e.IntrospectionEndpoint = e2.IntrospectionEndpoint
	}
	if e.UserinfoEndpoint == "" {
		e.UserinfoEndpoint = e2.UserinfoEndpoint
	}
	if e.EndSessionEndpoint == "" {
		e.EndSessionEndpoint = e2.EndSessionEndpoint
	}
	if e.RevocationEndpoint == "" {
		e.RevocationEndpoint = e2.RevocationEndpoint
	}
}

func newProvider(ctx context.Context, config ProviderConfig) (*provider, error) {
	var err error

	if config.ClientID == "" {
		return nil, fmt.Errorf("client id missing in configuration")
	}

	if config.Identifier == "" {
		config.Identifier = generateProviderIdentifier(&config)
	}

	provider := &provider{
		config: config,
		oauth2Config: &oauth2.Config{
			ClientID:     config.ClientID,
			ClientSecret: config.ClientSecret,
			Scopes:       config.Scopes,
			RedirectURL:  config.CallbackURL,
		},
		oidcConfig: &oidc.Config{
			ClientID: config.ClientID,
		},
	}

	// TODO: add option do defer
	if config.IssuerURL != "" {
		provider.oidcProvider, err = oidc.NewProvider(ctx, config.IssuerURL)
		if err != nil {
			return nil, err
		}
		endpoints := &Endpoints{}
		err := provider.oidcProvider.Claims(endpoints)
		if err != nil {
			return nil, err
		}

		// apply explicitly set settings
		provider.config.Endpoints.Merge(endpoints)
	}

	if provider.config.AuthorizationEndpoint == "" {
		return nil, fmt.Errorf("authorization endpoint not set")
	}
	if provider.config.TokenEndpoint == "" {
		return nil, fmt.Errorf("token endpoint not set")
	}

	provider.oauth2Config.Endpoint = oauth2.Endpoint{
		AuthURL:  provider.config.AuthorizationEndpoint,
		TokenURL: provider.config.TokenEndpoint,
	}

	return provider, nil
}

func generateProviderIdentifier(c *ProviderConfig) string {
	h := sha1.New()
	h.Write([]byte(c.IssuerURL))
	h.Write([]byte(c.ClientID))
	h.Write([]byte(c.AuthorizationEndpoint))
	h.Write([]byte(c.TokenEndpoint))
	return base64.RawStdEncoding.EncodeToString(h.Sum(nil))[:7]
}

type provider struct {
	config       ProviderConfig
	oidcProvider *oidc.Provider
	oidcConfig   *oidc.Config
	oauth2Config *oauth2.Config
}

type Tokens struct {
	oauth2.Token
	IDToken string `json:"id_token"`
}

func (p *provider) authCodeURL(ctx context.Context, state string, opts ...oauth2.AuthCodeOption) string {
	opts = append(opts, urlValuesIntoOpts(p.config.AuthorizationParameter)...)
	return p.oauth2Config.AuthCodeURL(state, opts...)
}

func urlValuesIntoOpts(urlValues url.Values) []oauth2.AuthCodeOption {
	opts := []oauth2.AuthCodeOption{}
	for parameter, values := range urlValues {
		for _, value := range values {
			opts = append(opts, oauth2.SetAuthURLParam(parameter, value))
		}
	}
	return opts
}

// rpInitiatedLogoutURL returns the logout URL if the end_session_endpoint is
// configured or an empty string otherwise.
func (p *provider) rpInitiatedLogoutURL(ctx context.Context, tokens *Tokens) string {
	q := url.Values{}
	if tokens.IDToken != "" {
		q.Add("id_token_hint", tokens.IDToken)
	}
	return p.config.EndSessionEndpoint + "?" + q.Encode()
}

func (p *provider) exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*Tokens, error) {
	oauth2Token, err := p.oauth2Config.Exchange(ctx, code, urlValuesIntoOpts(p.config.TokenParameters)...)
	if err != nil {
		return nil, err
	}

	idToken, idTokenAvailable := oauth2Token.Extra("id_token").(string)

	tokens := &Tokens{
		Token:   *oauth2Token,
		IDToken: idToken,
	}

	// OAuth2 only
	if !idTokenAvailable {
		return tokens, nil
	}

	if p.oidcProvider == nil {
		return tokens, fmt.Errorf("failed to verify id_token: verifier not configured")
	}
	// Parse and verify ID Token payload.
	_, err = p.oidcProvider.VerifierContext(ctx, p.oidcConfig).Verify(ctx, tokens.IDToken)
	if err != nil {
		return tokens, fmt.Errorf("failed to verify id_token: %w", err)
	}
	return tokens, nil
}

// refresh uses the refresh token of the existingTokens to obtain a new set of
// tokens. providers do not in every case return a new id_token. in these cases
// it returns uses the id_token of the existingTokens in the new token set.
func (p *provider) refresh(ctx context.Context, existingTokens *Tokens) (*Tokens, error) {
	if existingTokens.RefreshToken == "" {
		return nil, fmt.Errorf("no refresh token available")
	}

	// we deliberately only set the refresh_token to force the renewal
	refreshToken := &oauth2.Token{
		RefreshToken: existingTokens.RefreshToken,
	}
	oauth2Tokens, err := p.oauth2Config.TokenSource(ctx, refreshToken).Token()
	if err != nil {
		return nil, fmt.Errorf("token refresh failed: %w", err)
	}

	idToken, ok := oauth2Tokens.Extra("id_token").(string)
	// certain providers to not return new id_tokens on refresh.for these we keep the old token
	if !ok {
		idToken = existingTokens.IDToken
	}

	return &Tokens{
		Token:   *oauth2Tokens,
		IDToken: idToken,
	}, nil
}

// revoke revokes a token using the revocation endpoint. see
// https://www.rfc-editor.org/rfc/rfc7009.html#section-2.1 for details. usually
// you want to revoke the refresh_token because the RFC states that `If the
// particular token is a refresh token and the authorization server supports
// the revocation of access tokens, then the authorization server SHOULD also
// invalidate all access tokens based on the same authorization grant`.
func (p *provider) revoke(ctx context.Context, token string) error {
	if p.config.RevocationEndpoint == "" {
		return fmt.Errorf("provider has no revocation endpoint set")
	}

	body := url.Values{}
	body.Add("token", token)
	body.Add("client_id", p.config.ClientID)
	body.Add("client_secret", p.config.ClientSecret)

	req, err := http.NewRequestWithContext(ctx, "POST", p.config.RevocationEndpoint, strings.NewReader(body.Encode()))
	if err != nil {
		return fmt.Errorf("revocation failed: %w", err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("revocation failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 399 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1000))
		return fmt.Errorf("revocation failed: returned status code %d with body '%s'", resp.StatusCode, body)
	}
	return nil
}
