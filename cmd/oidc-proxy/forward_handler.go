package main

import (
	"crypto/tls"
	"net/http"
	"net/http/httputil"
	"net/url"

	oidcauth "github.com/dvob/oidc-auth"
)

type forwardHandlerConfig struct {
	useIDToken            bool
	tlsInsecureSkipVerify bool
}

// newForwardHandler returns a handler which forwards all requests to upstream
// and adds to every request the access token of the session as Authorization
// header.
func newForwardHandler(upstream string, config forwardHandlerConfig, modifyRequest func(r *http.Request)) (http.Handler, error) {
	targetURL, err := url.Parse(upstream)
	if err != nil {
		return nil, err
	}

	rewriteFunc := func(pr *httputil.ProxyRequest) {
		pr.SetURL(targetURL)
		pr.SetXForwarded()

		s := oidcauth.SessionFromContext(pr.In.Context())

		if config.useIDToken {
			if s != nil && s.HasIDToken() {
				pr.Out.Header.Set("Authorization", s.Tokens.Type()+" "+s.IDToken())
			}
		} else {
			if s != nil && s.HasAccessToken() {
				pr.Out.Header.Set("Authorization", s.Tokens.Type()+" "+s.AccessToken())
			}
		}

		if modifyRequest != nil {
			modifyRequest(pr.Out)
		}
	}

	// http11Upstream := httputil.NewSingleHostReverseProxy(targetURL)
	http11Transport := http.DefaultTransport.(*http.Transport).Clone()
	http11Transport.ForceAttemptHTTP2 = false
	http11Transport.TLSNextProto = make(map[string]func(authority string, c *tls.Conn) http.RoundTripper)

	if config.tlsInsecureSkipVerify {
		http11Transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}

	http11Upstream := &httputil.ReverseProxy{
		Rewrite:   rewriteFunc,
		Transport: http11Transport,
	}

	defaultTransport := http.DefaultTransport.(*http.Transport).Clone()

	if config.tlsInsecureSkipVerify {
		defaultTransport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}

	defaultUpstream := &httputil.ReverseProxy{
		Rewrite:   rewriteFunc,
		Transport: defaultTransport,
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Upgrade is only supported by HTTP/1.1
		if r.Proto == "HTTP/1.1" && r.Header.Get("Upgrade") != "" {
			http11Upstream.ServeHTTP(w, r)
		} else {
			defaultUpstream.ServeHTTP(w, r)
		}
	}), nil
}
