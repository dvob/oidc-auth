package oidcproxy

import (
	"fmt"
	"log/slog"
	"net/http"
)

type HTTPErrorHandler func(w http.ResponseWriter, r *http.Request, httpCode int, err error)

type PostCallbackHandler func(w http.ResponseWriter, r *http.Request, s *SessionContext)

func defaultPostCallbackHandler(sm *sessionManager, errorHandler HTTPErrorHandler, infoEndpoint string) func(w http.ResponseWriter, r *http.Request, s *SessionContext) {
	return func(w http.ResponseWriter, r *http.Request, s *SessionContext) {
		// persist new session
		err := sm.SetSession(w, r, s.Session)
		if err != nil {
			errorHandler(w, r, http.StatusInternalServerError, err)
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

func defaultErrorHandler(w http.ResponseWriter, r *http.Request, httpCode int, err error) {
	message := http.StatusText(httpCode)
	if err != nil {
		if userError, ok := err.(UserError); ok {
			message = userError.UserError()
		}
	}
	http.Error(w, message, httpCode)
}

func CallbackHandler(sm *sessionManager, postCallbackHandler PostCallbackHandler, errorHandler HTTPErrorHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		loginState := sm.GetLoginState(w, r)
		if loginState == nil {
			errorHandler(w, r, http.StatusBadRequest, fmt.Errorf("state missing"))
			return
		}

		sm.DeleteLoginState(w, r)

		state := r.URL.Query().Get("state")
		if state != loginState.State {
			errorHandler(w, r, http.StatusBadRequest, fmt.Errorf("state missmatch"))
			return
		}

		params := r.URL.Query()
		if params.Get("error") != "" {
			slog.Info("login failed", "error", params.Get("error"), "error_description", params.Get("error_description"))
			errorHandler(w, r, http.StatusInternalServerError, fmt.Errorf("error=%s, error_description=%s", params.Get("error"), params.Get("error_description")))
			return
		}

		if !params.Has("code") {
			slog.Info("login failed", "error", "code missing")
			errorHandler(w, r, http.StatusBadRequest, fmt.Errorf("code missing"))
			return

		}
		code := params.Get("code")

		provider, err := sm.providerSet.GetByID(loginState.ProviderID)
		if err != nil {
			slog.Error("invalid provider", "err", err)
			errorHandler(w, r, http.StatusBadRequest, fmt.Errorf("invalid provider id"))
			return
		}
		newSession, err := provider.Exchange(r.Context(), code)
		if err != nil {
			slog.Info("session initialization failed", "err", err)
			// TODO: could be 401
			errorHandler(w, r, http.StatusInternalServerError, err)
			return
		}

		slog.Info("session initiated", "refresh_token", newSession.HasRefreshToken())
		postCallbackHandler(w, r, &SessionContext{
			Session:  newSession,
			Provider: provider,
		})
	})
}
