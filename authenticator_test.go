package oidcauth

import (
	"context"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/http/httputil"
	"testing"

	"github.com/dvob/oidc-auth/testissuer"
	"github.com/stretchr/testify/require"
)

func newClient(t *testing.T, debug bool) *http.Client {
	transport := http.DefaultTransport
	if debug {
		transport = newLogTransport(t, transport, true)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		panic(err)
	}
	return &http.Client{
		Transport: transport,
		Jar:       jar,
	}
}

type testAuth struct {
	ts       *httptest.Server
	idp      *testissuer.Server
	oidcAuth *Authenticator
	handler  *http.ServeMux
}

func (t *testAuth) URL() string {
	return t.ts.URL
}

func (t *testAuth) Close() {
	t.ts.Close()
	t.idp.Close()
}

func newDefaultTestConfig() *Config {
	c := NewDefaultConfig()
	c.EncryptionKey = make([]byte, 32)
	_, err := rand.Read(c.EncryptionKey)
	if err != nil {
		panic(err)
	}

	c.HashKey = make([]byte, 64)
	_, err = rand.Read(c.HashKey)
	if err != nil {
		panic(err)
	}

	c.CookieConfig.Secure = false
	return c
}

// newTestComponents creates a new issuer
func newTestComponents(t *testing.T, config *Config, handler http.Handler) *testAuth {
	t.Helper()

	// prepare default configuration
	if config == nil {
		config = newDefaultTestConfig()
	}
	if len(config.Providers) == 0 {
		config.Providers = []ProviderConfig{{
			ClientID: "myclient",
		}}
	}

	// setup test issuer
	idp, err := testissuer.NewServer(nil)
	if err != nil {
		t.Fatal(err)
	}

	// setup providers based on test issuer
	for i := range config.Providers {
		config.Providers[i].IssuerURL = idp.IssuerURL
	}

	// setup app server unstarted that we get the callback url
	ts := httptest.NewUnstartedServer(nil)
	serverURL := "http://" + ts.Listener.Addr().String()
	config.CallbackURL = serverURL + "/auth/callback"

	// prepare oidc authenticator
	ctx := context.Background()
	oidcAuth, err := NewAuthenticator(ctx, config)
	if err != nil {
		t.Fatal(err)
	}

	authHandler := oidcAuth.FullMiddleware(handler)
	ts.Config.Handler = authHandler
	ts.Start()

	return &testAuth{
		ts:       ts,
		idp:      idp,
		oidcAuth: oidcAuth,
		handler:  authHandler,
	}
}

func TestFullMiddleware(t *testing.T) {
	var (
		debugLog = false
	)
	t.Run("login", func(t *testing.T) {
		var backendReq *http.Request
		backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			backendReq = r
		})

		tc := newTestComponents(t, nil, backend)

		c := newClient(t, debugLog)

		// expect redirect
		req, err := http.NewRequest("GET", tc.URL()+"/abc", nil)
		require.NoError(t, err)

		resp, err := c.Transport.RoundTrip(req)
		require.NoError(t, err)

		require.NotEmpty(t, resp.Header.Get("Location"), "request should be redirected to login page")
		require.Nil(t, backendReq)

		// login form
		req, err = http.NewRequest("GET", tc.URL()+"/abc", nil)
		require.NoError(t, err)

		resp, err = c.Do(req)
		require.NoError(t, err)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Contains(t, string(body), "Login Form")
		require.Nil(t, backendReq)
	})
	t.Run("login_multi", func(t *testing.T) {
		var backendReq *http.Request
		backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			backendReq = r
		})

		config := newDefaultTestConfig()
		config.Providers = []ProviderConfig{
			{
				ID:       "p1",
				Name:     "MyProvider1",
				ClientID: "myclient1",
			},
			{
				ID:       "p2",
				Name:     "MyProvider2",
				ClientID: "myclient2",
			},
		}

		tc := newTestComponents(t, config, backend)

		c := newClient(t, debugLog)

		// login form
		req, err := http.NewRequest("GET", tc.URL()+"/abc", nil)
		require.NoError(t, err)

		resp, err := c.Do(req)
		require.NoError(t, err)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Contains(t, string(body), "Sign in with")
		require.Contains(t, string(body), "MyProvider1")
		require.Contains(t, string(body), "MyProvider2")
		require.Nil(t, backendReq)

		c = newClient(t, debugLog)
		// login by calling login directly
		err = tc.idp.Login("myuser@foo.local", c)
		require.NoError(t, err)
		req, err = http.NewRequest("GET", tc.URL()+"/auth/login?provider=p1", nil)
		require.NoError(t, err)

		resp, err = c.Do(req)
		require.NoError(t, err)

		require.Equal(t, "/auth/info", resp.Request.URL.Path, "direct request to login should get redirected to session info")
		require.Nil(t, backendReq)
	})
}

type logTransport struct {
	t        *testing.T
	inner    http.RoundTripper
	dumpBody bool
}

func newLogTransport(t *testing.T, inner http.RoundTripper, body bool) *logTransport {
	if inner == nil {
		inner = http.DefaultTransport
	}
	return &logTransport{
		t:        t,
		inner:    inner,
		dumpBody: body,
	}
}

var _ http.RoundTripper = &logTransport{}

// RoundTrip implements http.RoundTripper.
func (l *logTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	out, _ := httputil.DumpRequest(req, l.dumpBody)
	l.t.Log(string(out))

	resp, err := l.inner.RoundTrip(req)

	out, _ = httputil.DumpResponse(resp, l.dumpBody)
	l.t.Log(string(out))
	return resp, err
}
