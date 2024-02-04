package oidcauth

import (
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// DebugHandler returns information about the session including the tokens.
func DebugHandler(sm *sessionManager, providers []*Provider) http.Handler {
	pcs := []ProviderConfig{}
	for _, p := range providers {
		config := p.Config()
		config.ID = p.ID()
		config.ClientSecret = "****"
		pcs = append(pcs, config)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, _ := sm.GetSession(w, r)
		data := struct {
			ProviderConfigs []ProviderConfig `json:"provider_configs"`
			Session         *Session         `json:"session"`
			SessionJWT      struct {
				AccessToken  *jwt `json:"access_token"`
				RefreshToken *jwt `json:"refresh_token"`
				IDToken      *jwt `json:"id_token"`
			} `json:"session_jwt"`
			Request *request `json:"request"`
		}{
			ProviderConfigs: pcs,
			Request:         newRequest(r),
		}
		if session != nil {
			data.Session = session.Session
			data.SessionJWT.AccessToken = readJWT(session.AccessToken())
			data.SessionJWT.RefreshToken = readJWT(session.RefreshToken())
			data.SessionJWT.IDToken = readJWT(session.IDToken())
		}

		w.Header().Add("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(data)
		if err != nil {
			slog.Info("failed to encode json in info handler", "err", err)
		}
	})

}

type request struct {
	Method     string      `json:"method"`
	Host       string      `json:"host"`
	URI        string      `json:"uri"`
	Protocol   string      `json:"protocol"`
	Header     http.Header `json:"header"`
	RemoteAddr string      `json:"remote_addr"`
}

func newRequest(r *http.Request) *request {
	return &request{
		Method:     r.Method,
		Host:       r.Host,
		URI:        r.RequestURI,
		Protocol:   r.Proto,
		Header:     r.Header,
		RemoteAddr: r.RemoteAddr,
	}
}

type jwt struct {
	Header   map[string]any `json:"header,omitempty"`
	Claims   map[string]any `json:"claims,omitempty"`
	Expiry   time.Time      `json:"expiry,omitempty"`
	IssuedAt time.Time      `json:"issued_at,omitempty"`
	Error    string         `json:"error,omitempty"`
}

func readJWT(token string) *jwt {
	if token == "" {
		return nil
	}

	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return nil
	}

	jwt := &jwt{}

	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		jwt.Error = err.Error()
		return jwt
	}
	claims, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		jwt.Error = err.Error()
		return jwt
	}

	err = json.Unmarshal(header, &jwt.Header)
	if err != nil {
		jwt.Error = err.Error()
		return jwt
	}
	err = json.Unmarshal(claims, &jwt.Claims)
	if err != nil {
		jwt.Error = err.Error()
		return jwt
	}

	if exp, ok := jwt.Claims["exp"]; ok {
		expTime, _ := exp.(float64)
		jwt.Expiry = time.Unix(int64(expTime), 0)
	}
	if iat, ok := jwt.Claims["iat"]; ok {
		iatTime, _ := iat.(float64)
		jwt.IssuedAt = time.Unix(int64(iatTime), 0)
	}

	return jwt
}
