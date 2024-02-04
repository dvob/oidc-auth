package oidcauth

import (
	"fmt"
	"log/slog"
	"net/http"
)

type PostCallbackHandler func(w http.ResponseWriter, r *http.Request, s *SessionContext)

func defaultPostCallbackHandler(sm *sessionManager, errorHandler ErrorHandler, infoEndpoint string) func(w http.ResponseWriter, r *http.Request, s *SessionContext) {
	return func(w http.ResponseWriter, r *http.Request, s *SessionContext) {
		// persist new session
		err := sm.SetSession(w, r, s.Session)
		if err != nil {
			errorHandler(w, r, err)
			return
		}

		loginState := sm.GetLoginState(w, r)

		originURI := loginState.URI
		if originURI == "" {
			http.Redirect(w, r, infoEndpoint, http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, loginState.URI, http.StatusSeeOther)
	}
}

func CallbackHandler(sm *sessionManager, postCallbackHandler PostCallbackHandler, errorHandler ErrorHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		loginState := sm.GetLoginState(w, r)
		if loginState == nil {
			errorHandler(w, r, ErrDirect(http.StatusBadRequest, fmt.Errorf("state missing")))
			return
		}

		sm.DeleteLoginState(w, r)

		state := r.URL.Query().Get("state")
		if state != loginState.State {
			errorHandler(w, r, ErrDirect(http.StatusBadRequest, fmt.Errorf("state missmatch")))
			return
		}

		params := r.URL.Query()
		if params.Get("error") != "" {
			errorHandler(w, r, ErrDirect(http.StatusInternalServerError, fmt.Errorf("error=%s, error_description=%s", params.Get("error"), params.Get("error_description"))))
			return
		}

		if !params.Has("code") {
			errorHandler(w, r, ErrDirect(http.StatusBadRequest, fmt.Errorf("authorization code missing")))
			return

		}
		code := params.Get("code")

		provider, err := sm.providerSet.GetByID(loginState.ProviderID)
		if err != nil {
			errorHandler(w, r, ErrDirect(http.StatusInternalServerError, fmt.Errorf("invalid provider id '%s'", loginState.ProviderID)))
			return
		}
		newSession, err := provider.Exchange(r.Context(), code)
		if err != nil {
			errorHandler(w, r, fmt.Errorf("session initialization failed: %w", err))
			return
		}

		slog.Debug("session initiated", "refresh_token", newSession.HasRefreshToken())
		postCallbackHandler(w, r, &SessionContext{
			Session:  newSession,
			Provider: provider,
		})
	})
}
