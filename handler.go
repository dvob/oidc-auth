package oidcproxy

import (
	"fmt"
	"log/slog"
	"net/http"
)

// LoadSessionHandler loads the session and makes it available in the context
// for subsequent handler.
func LoadSessionHandler(sm *sessionManager, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		currentSessionCtx, _ := sm.GetSession(w, r)
		r = r.WithContext(ContextWithSession(r.Context(), currentSessionCtx))
		next.ServeHTTP(w, r)
	})
}

// RemoveSessionHandler removes the session.
func RemoveSessionHandler(sm *sessionManager) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sm.RemoveSession(w, r)
	})
}

// AuthenticateHandler loads the session and sets it in the context. If there
// is no session available it initiates a login be redirecting the request to
// the login endpoint.
// If a session is available but it is no longer valid and if the session
// contains a refresh_token it tries to obtain a new session using the refresh
// token.
func AuthenticateHandler(sm *sessionManager, loginEndpoint string, next http.Handler) http.Handler {
	redirectToLogin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !(r.Method == "GET" || r.Method == "HEAD") {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		originURI := r.URL.RequestURI()
		sm.SetLoginState(w, r, &LoginState{URI: originURI})
		http.Redirect(w, r, loginEndpoint, http.StatusSeeOther)
	})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		currentSession, _ := sm.GetSession(w, r)
		if currentSession == nil {
			slog.Debug("no session available: initiate login")
			redirectToLogin(w, r)
			return
		}

		// run silent refresh or redirect to login if session expired
		if !currentSession.Valid() {
			if !currentSession.HasRefreshToken() {
				slog.Debug("no refresh token available: initiate login")
				redirectToLogin(w, r)
			}

			newSession, err := currentSession.Provider.Refresh(r.Context(), currentSession.Session)
			if err != nil {
				slog.Info("token refresh failed. initiate login", "err", err)
				redirectToLogin(w, r)
				return
			}

			slog.Info("token refreshed", "access_token", newSession.HasAccessToken(), "refresh_token", newSession.HasRefreshToken(), "id_token", newSession.HasIDToken())

			err = sm.SetSession(w, r, newSession)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}

			currentSession.Session = newSession
		}

		r = r.WithContext(ContextWithSession(r.Context(), currentSession))
		next.ServeHTTP(w, r)
	})
}

func RefreshHandler(sm *sessionManager) http.Handler {
	redirectToInfo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/info", http.StatusSeeOther)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO: return proper json response on accept json
		// TODO: on HTML set flash message
		session, _ := sm.GetSession(w, r)
		if session == nil {
			http.Error(w, "no session", http.StatusUnauthorized)
			return
		}

		newSession, err := session.Provider.Refresh(r.Context(), session.Session)
		if err != nil {
			slog.Info("session initialization after token refresh failed", "err", err)

			message := "token refresh failed"
			if userError, ok := err.(UserError); ok {
				message += ": " + userError.UserError()
			}
			http.Error(w, message, http.StatusInternalServerError)
			return
		}

		slog.Info("token refreshed", "access_token", newSession.HasAccessToken(), "refresh_token", newSession.HasRefreshToken(), "id_token", newSession.HasIDToken())

		err = sm.SetSession(w, r, newSession)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		redirectToInfo(w, r)
	})
}

// LogoutHandler deletes the session cookies, revokes the token (if supportd by
// the provider) and redirects to the end_session_uri of the provider (if
// supported by the provider).
func LogoutHandler(sm *sessionManager, postLogoutHandler http.Handler) http.Handler {
	if postLogoutHandler == nil {
		postLogoutHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, "logged out")
		})
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, _ := sm.GetSession(w, r)
		if session == nil {
			postLogoutHandler.ServeHTTP(w, r)
			return
		}

		// remove session (delete cookie)
		sm.RemoveSession(w, r)

		// revoke tokens
		if session.HasRefreshToken() {
			err := session.Provider.Revoke(r.Context(), session.RefreshToken())
			if err != nil && err != ErrNotSupported {
				slog.Warn("failed to revoke token", "err", err)
			}
		}

		// redirect to end session endpoint if available
		endSessionURL, err := session.Provider.EndSessionEndpoint(r.Context(), session.Session)
		if err != nil && err != ErrNotSupported {
			slog.Warn("failed to obtain end session endpoint", "err", err)
		}

		if err == nil {
			http.Redirect(w, r, endSessionURL, http.StatusSeeOther)
			return
		}

		postLogoutHandler.ServeHTTP(w, r)
	})
}
