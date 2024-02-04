package oidcauth

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// ErrNotSupported is returned if an action on a provider is called which is
// not supported. For example if you call Revoke but the provider does not have
// configured a revocation endpoint.
var ErrNotSupported = errors.New("not supported")

type ProviderConfig struct {
	// ID (optional) for the provider. This is espacially used in multi provider
	// scenarios where the provider ID is stored in the session to figure
	// out for each session to which provider it belongs.
	// If no ID is provided it is generated based on the configuration.
	ID string `json:"id,omitempty"`

	// Name (optional) is a descriptive name for the provider. It is used in multi
	// provider scenarios during the login process on the provider
	// selection screen.
	Name string `json:"name"`

	// IssuerURL is the URL for the OpenID discovery. For providers which
	// do not support OpenID discovery you can configure
	// AuthorizationEndpoint and TokenEndpoint instead.
	IssuerURL string `json:"issuer_url"`

	// ClientID
	ClientID string `json:"client_id"`

	// ClientSecret (optional) if not set the provider acts as a public
	// client.
	ClientSecret string `json:"client_secret"`

	// Scopes (optional) to use for the authorization.
	Scopes []string `json:"scopes"`

	// AuthorizationParameter (optional) are additional query parameters
	// for the authorization endpoint (e.g. resource).
	AuthorizationParameter url.Values `json:"authorization_parameters"`

	// TokenParameters (optional) are additional query parameters for the
	// token endpoint.
	TokenParameters url.Values `json:"token_parameters"`

	// CallbackURL used as redirect_uri
	CallbackURL string `json:"callback_url"`

	// PostLogoutRedirectURI (optional) is used during logout for the call
	// to the EndSessionEndpoint.
	PostLogoutRedirectURI string `json:"post_logout_redirect_uri"`

	// SetupSessionFunc allows to customize the Session based on the tokens
	// returned in the TokenResponse. For example exctract values from the
	// id_tokens of fetch additional information from a third-party servie
	// using the access_token. If SetupSessionFunc is nil only the defaultSessionSetupFunc is used
	SetupSessionFunc SessionSetupFunc `json:"-"`

	// Endpoints are usually discovered using OpenID discovery. If set
	// manual you can configure endpoints which can't be discovered or
	// overwrite endpoints from the discovery.
	Endpoints
}

type Endpoints struct {
	// AuthorizationEndpoint https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	// TokenEndpoint https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
	TokenEndpoint string `json:"token_endpoint"`
	// UserinfoEndpoint https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
	UserinfoEndpoint string `json:"userinfo_endpoint"`

	// EndSessionEndpoint https://openid.net/specs/openid-connect-rpinitiated-1_0.html#OPMetadata
	EndSessionEndpoint string `json:"end_session_endpoint"`

	// IntrospectionEndpoint (discovery has no specification)
	// See https://datatracker.ietf.org/doc/html/rfc7662
	IntrospectionEndpoint string `json:"introspection_endpoint"`

	// RevocationEndpoint (discovery has no specification)
	// See https://datatracker.ietf.org/doc/html/rfc7009
	RevocationEndpoint string `json:"revocation_endpoint"`
}

// Merge merges e2 into e
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

func (pc *ProviderConfig) clone() ProviderConfig {
	clone := *pc

	// Scopes
	clone.Scopes = make([]string, len(pc.Scopes))
	copy(clone.Scopes, pc.Scopes)

	// AuthorizationParameter
	clone.AuthorizationParameter = url.Values(http.Header(pc.AuthorizationParameter).Clone())

	// TokenParameters
	clone.TokenParameters = url.Values(http.Header(pc.TokenParameters).Clone())

	return clone
}

func NewProvider(ctx context.Context, config ProviderConfig) (*Provider, error) {
	var err error

	config = config.clone()

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
		oauth2AuthCodeOpts: urlValuesIntoOpts(config.AuthorizationParameter),
		oauth2TokenOpts:    urlValuesIntoOpts(config.TokenParameters),

		oidcConfig: &oidc.Config{
			ClientID:             config.ClientID,
			SupportedSigningAlgs: []string{"RS256", "ES384"},
		},
		sessionSetupFunc: sessionSetupFunc,
	}

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

		// apply discoverd endpoints. explicitly set endpoints take
		// precedence over the discoverd endpoints.
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
	id     string
	config *ProviderConfig

	oidcProvider *oidc.Provider
	oidcConfig   *oidc.Config

	oauth2Config       *oauth2.Config
	oauth2AuthCodeOpts []oauth2.AuthCodeOption
	oauth2TokenOpts    []oauth2.AuthCodeOption

	sessionSetupFunc SessionSetupFunc
}

// ID returns an identifier of the provider. If not set in ProviderConfig it gets calculated based on:
//   - IssuerURL
//   - ClientID
//   - AuthorizationEndpoint
//   - TokenEndpoint
func (p *Provider) ID() string { return p.id }

// String returns a string representation of the provider. Do not rely on the
// format.
func (p *Provider) String() string {
	if p.config.Name == "" {
		return p.ID()
	}
	return fmt.Sprintf("%s (%s)", p.config.Name, p.ID())
}

func (p *Provider) Config() ProviderConfig {
	return p.config.clone()
}

// AuthorizationEndpoint returns the authorization endpoint where redirect
// clients to initiate a login.
func (p *Provider) AuthorizationEndpoint(_ context.Context, state string) (string, error) {
	// NOTE: might return error in the future if the provider is setup asynchronously.
	return p.oauth2Config.AuthCodeURL(state, p.oauth2AuthCodeOpts...), nil
}

// Exchange performs the Access Token Request using code. See
// https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3. Based on the
// returned Access Token Response it returns a session (see SessionSetupFunc).
func (p *Provider) Exchange(ctx context.Context, code string) (*Session, error) {
	oauth2Token, err := p.oauth2Config.Exchange(ctx, code, p.oauth2AuthCodeOpts...)
	if err != nil {
		return nil, err
	}

	tr, err := p.intoTokenResponse(ctx, oauth2Token)
	if err != nil {
		return nil, err
	}

	return p.newSession(ctx, tr)
}

// Refresh uses the refresh token of an existing session to obtain a new
// session. See https://datatracker.ietf.org/doc/html/rfc6749#section-6. If the
// session has no refresh token it returns an error.
func (p *Provider) Refresh(ctx context.Context, session *Session) (*Session, error) {
	if session == nil {
		return nil, fmt.Errorf("no session")
	}

	if !session.HasRefreshToken() {
		return nil, fmt.Errorf("missing refresh token")
	}

	// we deliberately only set the refresh_token to force the renewal
	refreshTokenSource := &oauth2.Token{
		RefreshToken: session.RefreshToken(),
	}
	oauth2Tokens, err := p.oauth2Config.TokenSource(ctx, refreshTokenSource).Token()
	if err != nil {
		return nil, fmt.Errorf("token refresh failed: %w", err)
	}

	tr, err := p.intoTokenResponse(ctx, oauth2Tokens)
	if err != nil {
		return nil, err
	}

	return p.newSession(ctx, tr)
}

// Revoke revokes a token using the revocation endpoint. See
// https://www.rfc-editor.org/rfc/rfc7009.html#section-2.1 for details. Usually
// you want to revoke the refresh_token because the RFC states that `If the
// particular token is a refresh token and the authorization server supports
// the revocation of access tokens, then the authorization server SHOULD also
// invalidate all access tokens based on the same authorization grant`.
// Revoke does return ErrNotSupported if no revocation endpoint is configured.
func (p *Provider) Revoke(ctx context.Context, token string) error {
	if p.config.RevocationEndpoint == "" {
		return ErrNotSupported
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

// EndSessionEndpoint returns the logout URL for the RP initiated logout if the end_session_endpoint is
// configured or an empty string otherwise.
// https://openid.net/specs/openid-connect-rpinitiated-1_0.html
func (p *Provider) EndSessionEndpoint(_ context.Context, session *Session) (string, error) {
	if p.config.EndSessionEndpoint == "" {
		return "", ErrNotSupported
	}

	q := url.Values{}

	tokens := session.Tokens
	if tokens != nil && tokens.IDToken != "" {
		q.Add("id_token_hint", tokens.IDToken)
	}

	if p.config.PostLogoutRedirectURI != "" {
		q.Add("post_logout_redirect_uri", p.config.PostLogoutRedirectURI)
	}

	return p.config.EndSessionEndpoint + "?" + q.Encode(), nil
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

func (p *Provider) newSession(ctx context.Context, tr *TokenResponse) (*Session, error) {
	newSession := &Session{
		ProviderID: p.ID(),
	}
	err := p.sessionSetupFunc(ctx, p, tr, newSession)
	if err != nil {
		return nil, err
	}
	return newSession, nil
}

func (p *Provider) intoTokenResponse(ctx context.Context, oauth2Token *oauth2.Token) (*TokenResponse, error) {
	tokenResponse := &TokenResponse{
		Token: *oauth2Token,
	}

	idToken := oauth2Token.Extra("id_token")
	if idToken == nil {
		// request does not contain id_token
		return tokenResponse, nil
	}

	var ok bool
	tokenResponse.RawIDToken, ok = idToken.(string)
	if !ok {
		return tokenResponse, fmt.Errorf("id_token is not of type string")
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

type providerSet struct {
	providerList []*Provider
	providerMap  map[string]*Provider
}

func NewProviderSet(ctx context.Context, providerConfigs []ProviderConfig, modifier func(pc *ProviderConfig)) ([]*Provider, error) {
	providerList := []*Provider{}
	for _, config := range providerConfigs {
		config := config.clone()
		modifier(&config)

		slog.InfoContext(ctx, "init provider", "issuer_url", config.IssuerURL)
		provider, err := NewProvider(ctx, config)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize provider '%s': %w", config.IssuerURL, err)
		}

		providerList = append(providerList, provider)
	}
	return providerList, nil
}

func newProviderSet(providers ...*Provider) (*providerSet, error) {
	providerMap := map[string]*Provider{}
	for _, p := range providers {
		p := p
		if existing, ok := providerMap[p.ID()]; ok {
			return nil, fmt.Errorf("duplicate provider %s (%s) and %s (%s)", existing.config.Name, existing.config.IssuerURL, p.config.Name, p.config.IssuerURL)
		}

		providerMap[p.ID()] = p
	}
	return &providerSet{
		providerList: providers,
		providerMap:  providerMap,
	}, nil
}

func (ps *providerSet) GetByID(id string) (*Provider, error) {
	provider, ok := ps.providerMap[id]
	if !ok {
		return nil, fmt.Errorf("unknown provider with id '%s'", id)
	}
	return provider, nil
}

func (ps *providerSet) List() []*Provider {
	return ps.providerList
}
