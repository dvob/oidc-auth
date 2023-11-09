package oidcproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

func NewMainHandler(config *Config, next http.Handler) (http.Handler, error) {
	var (
		templateDir     string
		templateDevMode bool
	)

	tm, err := newTemplateManager(templateDir, templateDevMode)
	if err != nil {
		return nil, err
	}

	if config.CallbackURL == "" {
		return nil, fmt.Errorf("callback url not set")
	}

	providers, err := NewProviderSet(context.TODO(), config.Providers, func(pc *ProviderConfig) {
		if pc.CallbackURL == "" {
			pc.CallbackURL = config.CallbackURL
		}

		if pc.PostLogoutRedirectURI == "" {
			pc.PostLogoutRedirectURI = config.PostLogoutRediretURI
		}
	})
	if err != nil {
		return nil, err
	}

	providerSet, err := newProviderSet(providers...)
	if err != nil {
		return nil, err
	}

	sm, err := NewSessionManager(config.HashKey, config.EncryptKey, providerSet)
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	mux.Handle("/login", LoginHandler(sm, ProviderSelectionHandler(config.AppName, providers, tm)))
	mux.Handle("/callback", CallbackHandler(
		sm,
		defaultPostCallbackHandler(sm, defaultErrorHandler),
		defaultErrorHandler,
	))
	mux.Handle("/logout", LogoutHandler(sm, nil))
	mux.Handle("/info", NewDefaultSessionInfoHandler(sm, tm))

	mux.Handle("/debug", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cs := []ProviderConfig{}
		for _, p := range providers {
			cs = append(cs, p.Config())
		}

		json.NewEncoder(w).Encode(cs)
	}))
	mux.Handle("/", AuthenticateHandler(sm, "/login", next))
	return mux, nil
}
