package oidcauth

import (
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
)

type CookieOptions struct {
	Path     string
	Secure   bool
	HttpOnly bool
	Domain   string
	SameSite http.SameSite
	Duration time.Duration
}

func (co *CookieOptions) NewCookie(name, value string) *http.Cookie {
	var expires time.Time
	if co.Duration != 0 {
		expires = time.Now().Add(co.Duration)
	}
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     co.Path,
		Domain:   co.Domain,
		Expires:  expires,
		Secure:   co.Secure,
		HttpOnly: co.HttpOnly,
		SameSite: co.SameSite,
	}
}

type CookieManager struct {
	securecookie  *securecookie.SecureCookie
	cookieOptions CookieOptions
}

func NewDefaultCookieOptions() *CookieOptions {
	return &CookieOptions{
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

func NewCookieHandler(hashKey, encryptKey []byte) *CookieManager {
	return NewCookieHandlerWithOptions(hashKey, encryptKey, NewDefaultCookieOptions())
}

func NewCookieHandlerWithOptions(hashKey []byte, encryptKey []byte, options *CookieOptions) *CookieManager {
	sc := securecookie.New(hashKey, encryptKey)
	sc.MaxLength(0)

	if options == nil {
		options = NewDefaultCookieOptions()
	}

	return &CookieManager{
		securecookie:  sc,
		cookieOptions: *options,
	}
}

func (c *CookieManager) Set(w http.ResponseWriter, r *http.Request, name string, value any, opts ...func(*http.Cookie)) error {
	encodedValue, err := c.securecookie.Encode(name, value)
	if err != nil {
		return err
	}

	cookie := c.cookieOptions.NewCookie(name, encodedValue)
	for _, opt := range opts {
		opt(cookie)
	}
	SetCookie(w, r, cookie)
	return nil
}

func (c *CookieManager) Get(r *http.Request, name string, dstValue any) (bool, error) {
	cookies := getCookies(r, name)
	if len(cookies) == 0 {
		return false, nil
	}
	encodedValue := concatCookieValues(cookies)

	return true, c.securecookie.Decode(name, encodedValue, dstValue)
}

func (c *CookieManager) Delete(w http.ResponseWriter, r *http.Request, name string) {
	cookies := getCookies(r, name)
	if len(cookies) == 0 {
		return
	}

	for _, cookie := range cookies {
		deletionCookie := c.cookieOptions.NewCookie(cookie.Name, "")
		deletionCookie.Expires = time.Time{}
		deletionCookie.MaxAge = -1
		http.SetCookie(w, deletionCookie)
	}
}
