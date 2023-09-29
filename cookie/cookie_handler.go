package cookie

import (
	"net/http"

	"github.com/gorilla/securecookie"
)

type CookieHandler struct {
	securecookie  *securecookie.SecureCookie
	cookieOptions *http.Cookie
}

func NewCookieHandler(hashKey, encryptKey []byte) *CookieHandler {
	sc := securecookie.New(hashKey, encryptKey)
	sc.MaxLength(0)
	// sc.SetSerializer(newCompressSerializer())
	return &CookieHandler{
		securecookie: sc,
		cookieOptions: &http.Cookie{
			Path: "/",
		},
	}
}

func (c *CookieHandler) Set(w http.ResponseWriter, r *http.Request, name string, value any) error {
	encodedValue, err := c.securecookie.Encode(name, value)
	if err != nil {
		return err
	}

	cookie := *c.cookieOptions
	cookie.Name = name
	cookie.Value = encodedValue

	SetCookie(w, r, &cookie)
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

func (c *CookieHandler) Delete(w http.ResponseWriter, name string) {
	// TODO: handle multiple cookies
	cookie := *c.cookieOptions
	cookie.Name = name
	cookie.MaxAge = -1
	http.SetCookie(w, &cookie)
}
