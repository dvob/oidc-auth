package oidcauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// PathSet contains all pathes for the session info template.
type PathSet struct {
	// Login is the path to the login handler
	Login string

	// Logout is the path to the logout handler
	Logout string

	// Refresh is the path to the refresh handler
	Refresh string
}

// SessionInfoTemplateData are the parameters for the session info template.
type SessionInfoTemplateData struct {
	Session  *Session
	Provider *Provider
	Path     PathSet
}

func NewDefaultSessionInfoHandler(sm *sessionManager, tm *templateManager, pathSet PathSet, errorHandler ErrorHandler) http.Handler {
	renderSessionHandler := func(w http.ResponseWriter, r *http.Request, s *SessionContext) {
		var (
			session  *Session
			provider *Provider
		)
		if s != nil {
			session = s.Session
			provider = s.Provider
		}
		data := &SessionInfoTemplateData{
			Session:  session,
			Provider: provider,
			Path:     pathSet,
		}
		tm.servePage(w, "session_info_new", data)
	}
	return SessionInfoHandler(sm, renderSessionHandler, errorHandler)
}

// SessionInfoHandler gets the session from the request using sessionManager
// and then renders the session info using the renderSessionInfo function. If
// the request accepts the MIME type application/json it returns a JSON
// representation of the session.
func SessionInfoHandler(sm *sessionManager, renderSessionHandler func(w http.ResponseWriter, r *http.Request, s *SessionContext), errorHandler ErrorHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, _ := sm.GetSession(w, r)

		w.Header().Add("Cache-Control", "no-cache")
		contentType := r.Header.Get("Accept")
		if contentType == "application/json" {
			if session == nil {
				errorHandler(w, r, ErrDirect(http.StatusUnauthorized, fmt.Errorf("no session")))
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
				errorHandler(w, r, err)
				return
			}
			_, _ = w.Write(out)
			return
		}

		renderSessionHandler(w, r, session)
	})
}
