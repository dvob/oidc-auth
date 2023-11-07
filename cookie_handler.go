package oidcproxy

import (
	"net/http"

	"github.com/gorilla/securecookie"
)

type CookieHandler struct {
	securecookie  *securecookie.SecureCookie
	cookieOptions *http.Cookie
}

func NewDefaultCookieOptions() *http.Cookie {
	return &http.Cookie{
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

func NewCookieHandler(hashKey, encryptKey []byte) *CookieHandler {
	return NewCookieHandlerWithOptions(hashKey, encryptKey, NewDefaultCookieOptions())
}

func NewCookieHandlerWithOptions(hashKey []byte, encryptKey []byte, options *http.Cookie) *CookieHandler {
	if options == nil {
		options = NewDefaultCookieOptions()
	}
	sc := securecookie.New(hashKey, encryptKey)
	sc.MaxLength(0)
	// sc.SetSerializer(newCompressSerializer())
	return &CookieHandler{
		securecookie:  sc,
		cookieOptions: options,
	}
}

func (c *CookieHandler) Set(w http.ResponseWriter, r *http.Request, name string, value any, opts ...func(*http.Cookie)) error {
	encodedValue, err := c.securecookie.Encode(name, value)
	if err != nil {
		return err
	}

	newCookie := *c.cookieOptions
	cookie := &newCookie
	cookie.Name = name
	cookie.Value = encodedValue

	for _, opt := range opts {
		opt(cookie)
	}
	SetCookie(w, r, cookie)
	return nil
}

func (c *CookieHandler) Get(r *http.Request, name string, dstValue any) (bool, error) {
	cookies := getCookies(r, name)
	if len(cookies) == 0 {
		return false, nil
	}
	encodedValue := concatCookieValues(cookies)

	return true, c.securecookie.Decode(name, encodedValue, dstValue)
}

func (c *CookieHandler) Delete(w http.ResponseWriter, r *http.Request, name string) {
	cookies := getCookies(r, name)
	if len(cookies) == 0 {
		return
	}

	for _, cookie := range cookies {
		deletionCookie := *c.cookieOptions
		deletionCookie.Name = cookie.Name
		deletionCookie.MaxAge = -1
		http.SetCookie(w, &deletionCookie)
	}
}
