package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

func infoHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	info := struct {
		Hostname   string               `json:"hostname"`
		Request    *request             `json:"request"`
		TLS        *tls.ConnectionState `json:"tls"`
		JWT        *jwt                 `json:"jwt"`
		Session    *Session
		SessionJWT struct {
			AccessToken  *jwt `json:"access_token"`
			RefreshToken *jwt `json:"refresh_token"`
			IDToken      *jwt `json:"id_token"`
		} `json:"session_jwt"`
	}{}
	info.Hostname, _ = os.Hostname()
	info.Request = newRequest(r)
	info.TLS = r.TLS
	info.JWT = readJWT(readBearer(r))
	s := SessionFromContext(r.Context())
	info.Session = s
	if s != nil {
		info.SessionJWT.IDToken = readJWT(s.IDToken)
		info.SessionJWT.AccessToken = readJWT(s.OAuth2Tokens.AccessToken)
		info.SessionJWT.RefreshToken = readJWT(s.OAuth2Tokens.RefreshToken)
	}
	err := json.NewEncoder(w).Encode(info)
	if err != nil {
		log.Println("failed to encode json:", err)
	}
}

type request struct {
	Method     string      `json:"method"`
	Host       string      `json:"host"`
	URI        string      `json:"uri"`
	Protocol   string      `json:"protocol"`
	Header     http.Header `json:"header"`
	RemoteAddr string      `json:"remote_addr"`
	// TLS evtl.
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

func readBearer(r *http.Request) string {
	_, token, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	return token
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
