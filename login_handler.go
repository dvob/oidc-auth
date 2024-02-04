package oidcauth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
)

// LoginHandler returns a handler which sets a state and then redirects the
// request to the authorization endpoint of the provider. If multiple providers
// are configured the provider is selected via the query paramter
// provider=<providerID>.  If multiple providers are configured
// providerSelectionHandler can be used to render a provider selection dialog.
func LoginHandler(sm *sessionManager, providerSelectionHandler http.Handler, errorHandler ErrorHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerID := r.URL.Query().Get("provider")

		// If provider is not set and there is only one configured we use that one
		providers := sm.providerSet.List()
		if providerID == "" && len(providers) == 1 {
			providerID = providers[0].ID()
		}

		if providerID == "" {
			if providerSelectionHandler == nil {
				http.Error(w, "provider not set", http.StatusBadRequest)
				return
			}
			providerSelectionHandler.ServeHTTP(w, r)
			return
		}

		provider, err := sm.providerSet.GetByID(providerID)
		if err != nil {
			errorHandler(w, r, ErrDirect(http.StatusBadRequest, fmt.Errorf("invalid provider '%s'", providerID)))
			return
		}

		const STATE_LENGTH = 10
		stateStr, err := randString(STATE_LENGTH)
		if err != nil {
			errorHandler(w, r, err)
			return
		}

		state := sm.GetLoginState(w, r)
		if state == nil {
			state = &LoginState{
				ProviderID: providerID,
				State:      stateStr,
			}
		} else {
			state.ProviderID = providerID
			state.State = stateStr
		}

		err = sm.SetLoginState(w, r, state)
		if err != nil {
			errorHandler(w, r, err)
			return
		}

		redirectURL, err := provider.AuthorizationEndpoint(r.Context(), state.State)
		if err != nil {
			errorHandler(w, r, err)
			return
		}
		slog.DebugContext(r.Context(), "redirect for authentication", "url", redirectURL)
		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
	})
}

// ProviderSelectionHandler returns a handler which shows a provider selection
// dialog.
func ProviderSelectionHandler(appName string, providers []*Provider, tm *templateManager) http.Handler {
	type LoginProviderData struct {
		Name string
		Href string
	}

	loginProviderData := struct {
		Name      string
		Providers []LoginProviderData
	}{
		Name: appName,
	}

	for _, provider := range providers {
		parameters := url.Values{}
		parameters.Add("provider", provider.ID())

		loginProviderData.Providers = append(loginProviderData.Providers, LoginProviderData{
			Name: provider.config.Name,
			Href: "?" + parameters.Encode(),
		})
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Cache-Control", "no-cache")
		tm.servePage(w, "login_provider_selection", loginProviderData)
	})
}

func randString(randomBytesLen int) (string, error) {
	randomBytes := make([]byte, randomBytesLen)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(randomBytes), nil
}
