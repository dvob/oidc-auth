package oidcproxy

import (
	"log/slog"
	"net/http"
	"strings"
)

type sessionManager struct {
	cookieHandler        *CookieHandler
	sessionCookieName    string
	loginStateCookieName string
	providerSet          *providerSet
	logger               *slog.Logger
}

func newSessionManager(hashKey, encryptionKey []byte, providerSet *providerSet) *sessionManager {
	cookieHandler := NewCookieHandler(hashKey, encryptionKey)
	return &sessionManager{
		cookieHandler:        cookieHandler,
		loginStateCookieName: "oprox_state",
		sessionCookieName:    "oprox",
		providerSet:          providerSet,
		logger:               slog.Default(),
	}
}

type SessionContext struct {
	*Session
	Provider *Provider
}

// GetSession returns the SessionContext for the Request if available.
func (sm *sessionManager) GetSession(w http.ResponseWriter, r *http.Request) (*SessionContext, error) {
	sessionCtx := SessionFromContext(r.Context())
	if sessionCtx != nil {
		return sessionCtx, nil
	}
	s := &Session{}
	ok, err := sm.cookieHandler.Get(r, sm.sessionCookieName, s)
	if !ok {
		return nil, nil
	}
	if err != nil {
		sm.logger.Info("failed to decode session", "err", err)
		sm.RemoveSession(w, r)
		return nil, err
	}
	provider, err := sm.providerSet.GetByID(s.ProviderID)
	if err != nil {
		sm.logger.Info("session with invalid provider", "err", err)
		sm.RemoveSession(w, r)
		return nil, err
	}
	return &SessionContext{
		Session:  s,
		Provider: provider,
	}, nil
}

func (sm *sessionManager) SetSession(w http.ResponseWriter, r *http.Request, s *Session) error {
	if s == nil {
		sm.RemoveSession(w, r)
		return nil
	}
	err := sm.cookieHandler.Set(w, r, sm.sessionCookieName, s)
	if err != nil {
		sm.logger.Error("failed to encode session state", "err", err)
		return err
	}
	return nil
}

func (sm *sessionManager) RemoveSession(w http.ResponseWriter, r *http.Request) {
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

type LoginState struct {
	ProviderID string
	State      string
	URI        string
}

type LoginStateContext struct {
	*LoginState
	provider *Provider
}

func (sm *sessionManager) GetLoginState(w http.ResponseWriter, r *http.Request) *LoginState {
	loginState := &LoginState{}
	ok, err := sm.cookieHandler.Get(r, sm.loginStateCookieName, loginState)
	if !ok {
		return nil
	}
	if err != nil {
		slog.Info("failed to decode login state", "err", err)
		sm.DeleteLoginState(w, r)
		return nil
	}
	return loginState
}

func (sm *sessionManager) SetLoginState(w http.ResponseWriter, r *http.Request, l *LoginState) error {
	err := sm.cookieHandler.Set(w, r, sm.loginStateCookieName, l)
	if err != nil {
		slog.Error("failed to encode login state", "err", err)
	}
	return err
}

func (sm *sessionManager) DeleteLoginState(w http.ResponseWriter, r *http.Request) {
	sm.cookieHandler.Delete(w, r, sm.loginStateCookieName)
}
