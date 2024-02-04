package oidcauth

import (
	"crypto/tls"
	"net/http"
	"net/http/httputil"
	"net/url"
)

// newForwardHandler returns a handler which forwards all requests to upstream
// and adds to every request the access token of the session as Authorization
// header.
func newForwardHandler(upstream string, modifyRequest func(r *http.Request)) (http.Handler, error) {
	targetURL, err := url.Parse(upstream)
	if err != nil {
		return nil, err
	}

	rewriteFunc := func(pr *httputil.ProxyRequest) {
		pr.SetURL(targetURL)
		pr.SetXForwarded()
		if modifyRequest != nil {
			modifyRequest(pr.Out)
		}
	}

	// http11Upstream := httputil.NewSingleHostReverseProxy(targetURL)
	http11Transport := http.DefaultTransport.(*http.Transport).Clone()
	http11Transport.ForceAttemptHTTP2 = false
	http11Transport.TLSNextProto = make(map[string]func(authority string, c *tls.Conn) http.RoundTripper)

	http11Upstream := &httputil.ReverseProxy{
		Rewrite:   rewriteFunc,
		Transport: http11Transport,
	}

	// defaultUpstream := httputil.NewSingleHostReverseProxy(targetURL)

	defaultTransport := http.DefaultTransport.(*http.Transport).Clone()
	defaultUpstream := &httputil.ReverseProxy{
		Rewrite:   rewriteFunc,
		Transport: defaultTransport,
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := SessionFromContext(r.Context())

		if s != nil && s.HasAccessToken() {
			r.Header.Set("Authorization", s.Tokens.Type()+" "+s.AccessToken())
		}

		// Upgrade is only supported by HTTP/1.1
		if r.Proto == "HTTP/1.1" && r.Header.Get("Upgrade") != "" {
			http11Upstream.ServeHTTP(w, r)
		} else {
			defaultUpstream.ServeHTTP(w, r)
		}
	}), nil
}
