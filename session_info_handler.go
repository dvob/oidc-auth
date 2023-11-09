package oidcproxy

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
)

func NewDefaultSessionInfoHandler(sm *sessionManager, tm *templateManager) http.Handler {
	renderSessionHandler := func(w http.ResponseWriter, r *http.Request, s *SessionContext) {
		tm.servePage(w, "session_info_new", s)

	}
	return SessionInfoHandler(sm, renderSessionHandler)
}

func SessionInfoHandler(sm *sessionManager, renderSessionHandler func(w http.ResponseWriter, r *http.Request, s *SessionContext)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, _ := sm.GetSession(w, r)

		w.Header().Add("Cache-Control", "no-cache")
		contentType := r.Header.Get("Accept")
		if contentType == "application/json" {
			if session == nil {
				http.Error(w, "no session", http.StatusUnauthorized)
				return
			}

			sessionInfo := struct {
				// Active returns true if there is a valid session
				Active bool      `json:"active"`
				User   *User     `json:"user,omitempty"`
				Expiry time.Time `json:"expiry,omitempty"`
			}{
				Active: session.Valid(),
				Expiry: session.Expiry,
				User:   session.User,
			}

			w.Header().Add("Content-Type", "application/json")
			out, err := json.Marshal(&sessionInfo)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				slog.Error("failed to marshal session info", "err", err)
				return
			}
			w.Write(out)
			return
		}

		renderSessionHandler(w, r, session)
	})
}
