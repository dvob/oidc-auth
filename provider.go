package oidcproxy

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type ProviderConfig struct {
	ID                     string           `json:"id,omitempty"`
	Name                   string           `json:"name"`
	IssuerURL              string           `json:"issuer_url"`
	ClientID               string           `json:"client_id"`
	ClientSecret           string           `json:"client_secret"`
	Scopes                 []string         `json:"scopes"`
	AuthorizationParameter url.Values       `json:"authorization_parameters"`
	TokenParameters        url.Values       `json:"token_parameters"`
	CallbackURL            string           `json:"callback_url"`
	PostLogoutRedirectURI  string           `json:"post_logout_redirect_uri"`
	SetupSessionFunc       SessionSetupFunc `json:"-"`
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

func NewProvider(ctx context.Context, config ProviderConfig) (*Provider, error) {
	var err error

	if config.ClientID == "" {
		return nil, fmt.Errorf("client id missing in configuration")
	}

	sessionSetupFunc := defaultSessionSetupFunc
	if config.SetupSessionFunc != nil {
		sessionSetupFunc = ChainSessionSetupFunc(defaultSessionSetupFunc, config.SetupSessionFunc)
	}

	providerID := config.ID
	if len(providerID) == 0 {
		providerID = generateProviderIdentifier(&config)
	}

	provider := &Provider{
		id:     providerID,
		config: &config,
		oauth2Config: &oauth2.Config{
			ClientID:     config.ClientID,
			ClientSecret: config.ClientSecret,
			Scopes:       config.Scopes,
			RedirectURL:  config.CallbackURL,
		},
		oidcConfig: &oidc.Config{
			ClientID: config.ClientID,
		},
		sessionSetupFunc: sessionSetupFunc,
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

type Provider struct {
	id               string
	config           *ProviderConfig
	oidcProvider     *oidc.Provider
	oidcConfig       *oidc.Config
	oauth2Config     *oauth2.Config
	sessionSetupFunc SessionSetupFunc
}

func (p *Provider) ID() string { return p.id }

func (p *Provider) String() string {
	if p.config.Name == "" {
		return p.ID()
	}
	return fmt.Sprintf("%s (%s)", p.config.Name, p.ID())
}

func (p *Provider) Config() ProviderConfig {
	providerConfig := *p.config
	return providerConfig
}

type TokenResponse struct {
	oauth2.Token
	RawIDToken string
	IDToken    *oidc.IDToken
}

func (p *Provider) authCodeURL(ctx context.Context, state string, opts ...oauth2.AuthCodeOption) string {
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
// https://openid.net/specs/openid-connect-rpinitiated-1_0.html
func (p *Provider) rpInitiatedLogoutURL(ctx context.Context, tokens *Tokens) string {
	q := url.Values{}
	if tokens != nil && tokens.IDToken != "" {
		q.Add("id_token_hint", tokens.IDToken)
	}
	if p.config.PostLogoutRedirectURI != "" {
		q.Add("post_logout_redirect_uri", p.config.PostLogoutRedirectURI)
	}
	return p.config.EndSessionEndpoint + "?" + q.Encode()
}

func (p *Provider) exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*TokenResponse, error) {
	oauth2Token, err := p.oauth2Config.Exchange(ctx, code, urlValuesIntoOpts(p.config.TokenParameters)...)
	if err != nil {
		return nil, err
	}

	return p.intoTokenResponse(ctx, oauth2Token)
}

func (p *Provider) newSession(ctx context.Context, tr *TokenResponse) (*Session, error) {
	newSession := &Session{
		ProviderIdentifier: p.ID(),
	}
	err := p.sessionSetupFunc(ctx, p, tr, newSession)
	if err != nil {
		return nil, err
	}
	return newSession, nil
}

func (p *Provider) intoTokenResponse(ctx context.Context, oauth2Token *oauth2.Token) (*TokenResponse, error) {
	idToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("inavlid type for id_token")
	}

	tokenResponse := &TokenResponse{
		Token:      *oauth2Token,
		RawIDToken: idToken,
	}

	// OAuth2 only
	if idToken == "" {
		return tokenResponse, nil
	}

	if p.oidcProvider == nil {
		return tokenResponse, fmt.Errorf("failed to verify id_token: verifier not configured")
	}

	// Parse and verify ID Token payload.
	var err error
	tokenResponse.IDToken, err = p.oidcProvider.VerifierContext(ctx, p.oidcConfig).Verify(ctx, tokenResponse.RawIDToken)
	if err != nil {
		return tokenResponse, fmt.Errorf("failed to verify id_token: %w", err)
	}
	return tokenResponse, nil
}

// refresh uses the refresh token of the existingTokens to obtain a new set of
// tokens. providers do not in every case return a new id_token. in these cases
// it returns uses the id_token of the existingTokens in the new token set.
func (p *Provider) refresh(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	// we deliberately only set the refresh_token to force the renewal
	refreshTokenSource := &oauth2.Token{
		RefreshToken: refreshToken,
	}
	oauth2Tokens, err := p.oauth2Config.TokenSource(ctx, refreshTokenSource).Token()
	if err != nil {
		return nil, fmt.Errorf("token refresh failed: %w", err)
	}

	return p.intoTokenResponse(ctx, oauth2Tokens)
}

// revoke revokes a token using the revocation endpoint. see
// https://www.rfc-editor.org/rfc/rfc7009.html#section-2.1 for details. usually
// you want to revoke the refresh_token because the RFC states that `If the
// particular token is a refresh token and the authorization server supports
// the revocation of access tokens, then the authorization server SHOULD also
// invalidate all access tokens based on the same authorization grant`.
func (p *Provider) revoke(ctx context.Context, token string) error {
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

type UserError interface {
	UserError() string
}

type userError struct {
	userErrorMessage string
	err              error
}

func (ue *userError) Error() string     { return ue.err.Error() }
func (ue *userError) UserError() string { return ue.userErrorMessage }
func (ue *userError) Unwrap() error     { return ue.err }

func NewUserError(err error, code int, userErrorMessage string) *userError {
	if err == nil {
		err = fmt.Errorf(userErrorMessage)
	}
	return &userError{
		userErrorMessage: userErrorMessage,
		err:              err,
	}
}

type ClaimCheckFunc func(claims map[string]any) error

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
		return claimCheckFunc(claims)
	}
}

type SessionSetupFunc func(ctx context.Context, p *Provider, t *TokenResponse, s *Session) error

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
		message := fmt.Sprintf("You are not authorized. You need to be a member of one of theses groups: %s", strings.Join(groups, ", "))
		return NewUserError(nil, 401, message)
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

var defaultSessionSetupFunc SessionSetupFunc = func(ctx context.Context, p *Provider, t *TokenResponse, s *Session) error {
	const defaultSessionDuration = time.Minute * 15

	s.Tokens = &Tokens{
		Token:   t.Token,
		IDToken: t.RawIDToken,
	}

	if t.Token.Expiry.IsZero() {
		s.Expiry = time.Now().Add(defaultSessionDuration)
	} else {
		s.Expiry = t.Token.Expiry
	}

	if t.IDToken == nil {
		return nil
	}

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
