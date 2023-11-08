package oidcproxy

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
)

type sessionManager struct {
	cookieHandler     *CookieHandler
	sessionCookieName string
	providerMap       map[string]*Provider
	logger            *slog.Logger
}

func newSessionManager(hashKey, encryptionKey []byte, providerMap map[string]*Provider) *sessionManager {
	cookieHandler := NewCookieHandler(hashKey, encryptionKey)
	return &sessionManager{
		cookieHandler:     cookieHandler,
		sessionCookieName: "oprox",
		providerMap:       providerMap,
		logger:            slog.Default(),
	}
}

type SessionContext struct {
	Session  *Session
	Provider *Provider
}

func (sm *sessionManager) Get(w http.ResponseWriter, r *http.Request) (*SessionContext, error) {
	s := &Session{}
	ok, err := sm.cookieHandler.Get(r, sm.sessionCookieName, s)
	if !ok {
		return nil, nil
	}
	if err != nil {
		sm.logger.Info("failed to decode session", "err", err)
		sm.Remove(w, r)
		return nil, err
	}
	provider, ok := sm.providerMap[s.ProviderID]
	if !ok {
		sm.logger.Info("session with unknown provider", "identifier", s.ProviderID)
		sm.Remove(w, r)
		return nil, fmt.Errorf("unknown provider identifier '%s'", s.ProviderID)
	}
	return &SessionContext{
		Session:  s,
		Provider: provider,
	}, nil
}

func (sm *sessionManager) Set(w http.ResponseWriter, r *http.Request, s *Session) error {
	if s == nil {
		sm.Remove(w, r)
		return nil
	}
	err := sm.cookieHandler.Set(w, r, sm.sessionCookieName, s)
	if err != nil {
		sm.logger.Error("failed to encode session state", "err", err)
		return err
	}
	return nil
}

func (sm *sessionManager) Remove(w http.ResponseWriter, r *http.Request) {
	sm.cookieHandler.Delete(w, r, sm.sessionCookieName)
}

func (sm *sessionManager) RemoveCookie(r *http.Request) {
	cookies := r.Cookies()
	r.Header.Del("Cookie")
	for _, c := range cookies {
		if c.Name == sm.sessionCookieName || strings.HasPrefix(c.Name, sm.sessionCookieName+"_") {
			continue
		}
		r.AddCookie(c)
	}
}
