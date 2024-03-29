package oidcauth

import (
	"fmt"
	"net/http"
	"net/url"
	pathpkg "path"
)

type Config struct {
	// OAuth2 / OIDC
	Providers []ProviderConfig

	// CallbackURL is the url under which the callback path is reachable
	CallbackURL string

	// PostLogoutRedirectURI is the URL where you get redirected after an
	// RP initiated logut
	PostLogoutRediretURI string

	// BasePath is the path under which the other pathes get mapped
	BasePath string

	// LoginPath is the path under which the login flow gets initiated.
	LoginPath string

	// CallbackPath handle the oauth2 callback. It defaults to the path of
	// the CallbackURL if not specified.
	CallbackPath string

	// SessionInfoPath
	SessionInfoPath string

	// RefreshPath performs an explicit refresh
	RefreshPath string

	// LogoutPath deletes cookie, revokes token and redirect to IDPs logout
	// URL if available
	LogoutPath string

	// The external pathes are the paths under which the endpoint is
	// reachable from externally. If not set this defaults to the internal
	// path (same field without External prefix). These variables are only
	// required if between the client and this component the path gets
	// rewritten.
	// For example if you have an entry proxy (ingress) which routes
	// requests from entry.com/myapp/auth/info to myapp.com/auth/info you
	// have to configure a ExternalBasePath of /myapp.
	ExternalBasePath        string
	ExternalLoginPath       string
	ExternalSessionInfoPath string
	ExternalRefreshPath     string
	ExternalLogoutPath      string

	// secure cookie
	HashKey       []byte
	EncryptionKey []byte
	CookieConfig  *CookieOptions

	// AppName is used in templates. It is shown on the provider selection
	// to indicate where you are login into.
	AppName string

	TemplateDir     string
	TemplateDevMode bool

	// GetRequestID is used in the default error handler if set. It returns
	// the request id along with the error message.
	GetRequestID func(r *http.Request) string
}

func NewDefaultConfig() *Config {
	return &Config{
		AppName:         "OIDC Proxy",
		BasePath:        "/auth",
		LoginPath:       "/login",
		SessionInfoPath: "/info",
		RefreshPath:     "/refresh",
		LogoutPath:      "/logout",
		TemplateDevMode: false,
		CookieConfig:    NewDefaultCookieOptions(),
	}
}

// Prepare sets derived defaults and validates configuration.
func (c *Config) PrepareAndValidate() error {
	// callback url can only be empty if every provider has configured its
	// callback url explicitly
	if c.CallbackURL == "" {
		for _, providerConfig := range c.Providers {
			if providerConfig.CallbackURL == "" {
				return fmt.Errorf("callback url not set")
			}
		}
	}

	callbackURL, err := url.Parse(c.CallbackURL)
	if err != nil {
		return fmt.Errorf("invalid callback url '%s': %w", c.CallbackURL, err)
	}

	// derive callbackPath from callbackURL if callbackPath is not explicitly set
	if c.CallbackPath == "" && c.CallbackURL == "" {
		return fmt.Errorf("callback path and callback url are not configured")
	}

	if c.CallbackPath == "" {
		c.CallbackPath = callbackURL.Path
	} else {
		c.CallbackPath = c.BasePath + c.CallbackPath
	}

	// validate cookie keys
	if !(len(c.HashKey) == 32 || len(c.HashKey) == 64) {
		return fmt.Errorf("hash key is missing or has invalid key length. a length of 32 or 64 is required")
	}
	if !(len(c.EncryptionKey) == 0 || len(c.EncryptionKey) == 32 || len(c.EncryptionKey) == 64) {
		return fmt.Errorf("encryption kes is missing or has invalid key length. a length of 32 or 64 is required")
	}

	// Login
	c.LoginPath, c.ExternalLoginPath = preparePath(c.LoginPath, c.ExternalLoginPath, c.BasePath, c.ExternalBasePath)
	// Logout
	c.LogoutPath, c.ExternalLogoutPath = preparePath(c.LogoutPath, c.ExternalLogoutPath, c.BasePath, c.ExternalBasePath)
	// Refresh
	c.RefreshPath, c.ExternalRefreshPath = preparePath(c.RefreshPath, c.ExternalRefreshPath, c.BasePath, c.ExternalBasePath)
	// Info
	c.SessionInfoPath, c.ExternalSessionInfoPath = preparePath(c.SessionInfoPath, c.ExternalSessionInfoPath, c.BasePath, c.ExternalBasePath)
	return nil
}

func preparePath(path string, externalPath string, base string, externalBase string) (resultingPath string, resultingExternalPath string) {
	if base != "" {
		path = pathpkg.Join(base, path)
	}

	if externalPath == "" {
		externalPath = path
	}

	if externalBase != "" {
		externalPath = pathpkg.Join(externalPath, externalPath)
	}

	return path, externalPath
}
