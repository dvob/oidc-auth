package cookie

import (
	"net/http"
	"strconv"
	"strings"
)

const (
	MAX_COOKIE_SIZE = 4096
	// According to
	// https://stackoverflow.com/questions/3326210/can-http-headers-be-too-big-for-browsers
	// chrome does not handle more than 256k of total headers. Hence we do
	// not have to support more than 64 cookies (256k / 4k)
	MAX_COOKIE_COUNT = 64
)

// SetCookie splits a cookie with a big value into multiple cookies with
// corresponding suffixes to the cookie name (e.g. <name>_0, <name>_1). Based
// on the request old cookies which are no longer required are deleted.
func SetCookie(w http.ResponseWriter, r *http.Request, c *http.Cookie) {
	// generate new cookies
	cs := splitCookie(c)

	// remove no longer used cookies in the case where the new value is smaller
OUTER:
	for _, existingCookie := range r.Cookies() {
		if !strings.HasPrefix(existingCookie.Name, c.Name+"_") {
			continue
		}
		for _, newCookie := range cs {
			// this cookie name is still in use by the new cookies
			if newCookie.Name == existingCookie.Name {
				continue OUTER
			}
		}
		// this cookie is no longer in use. delete it
		delCookie := *existingCookie
		delCookie.Value = ""
		delCookie.MaxAge = -1
		http.SetCookie(w, &delCookie)
	}

	// set new cookies
	for _, c := range cs {
		http.SetCookie(w, c)
	}
}

func GetCookieValue(r *http.Request, name string) (string, error) {
	cookies := getCookies(r, name)
	if cookies == nil {
		return "", http.ErrNoCookie
	}
	return concatCookieValues(cookies), nil
}

func getCookies(r *http.Request, name string) []*http.Cookie {
	cookie, _ := r.Cookie(name)
	if cookie == nil {
		return nil
	}

	cookies := make([]*http.Cookie, 1, 8)
	cookies[0] = cookie

	for i := 0; i < MAX_COOKIE_COUNT; i++ {
		cookie, _ := r.Cookie(name + "_" + strconv.Itoa(i))
		if cookie == nil {
			break
		}
		cookies = append(cookies, cookie)
	}
	return cookies
}

// Concat all values of cookies.
func concatCookieValues(cs []*http.Cookie) string {
	var value strings.Builder
	for _, c := range cs {
		value.WriteString(c.Value)
	}
	return value.String()
}

func splitCookie(c *http.Cookie) []*http.Cookie {
	// We substract the name, because the name is going to change if we need multiple cookies (<cookie_name>_N).
	cookieMetaDataLen := getCookieMetadataLen(c) - len(c.Name)
	maxCookieSize := MAX_COOKIE_SIZE - (cookieMetaDataLen + len(c.Name))

	// Value fits into single cookie
	if len(c.Value) <= maxCookieSize {
		return []*http.Cookie{c}
	}

	// Split value into multiple cookies
	cookies := make([]*http.Cookie, 0, 8)
	newCookie := *c
	newCookie.Value = c.Value[0:maxCookieSize]
	cookies = append(cookies, &newCookie)
	idx := maxCookieSize
	count := 0
	for idx < len(c.Value) {

		name := c.Name + "_" + strconv.Itoa(count)
		count++

		// we remove the old name but add the new one which slighlty reduces the chunk size
		maxCookieSize = MAX_COOKIE_SIZE - (cookieMetaDataLen + len(name))
		end := idx + maxCookieSize

		if end > len(c.Value) {
			end = len(c.Value)
		}

		newCookie := *c
		newCookie.Name = name
		newCookie.Value = c.Value[idx:end]
		cookies = append(cookies, &newCookie)
		idx += maxCookieSize
	}
	return cookies
}

// getCookieMetadataLen calculates the length of a cookie without the value.
// This function is mostly an adapted copy of the http.Cookie.String() method.
func getCookieMetadataLen(c *http.Cookie) int {
	metaDataLen := len(c.Name + "=")

	if len(c.Path) > 0 {
		metaDataLen += len("; Path=")
		// TODO: sanitize Path
		metaDataLen += len(c.Path)
	}

	if len(c.Domain) > 0 {
		// TODO: invalid domains are not added
		metaDataLen += len("; Domain=")
		domainLen := len(c.Domain)
		if c.Domain[0] == '.' {
			domainLen -= 1
		}
		metaDataLen += domainLen
	}

	if c.Expires.Year() >= 1601 {
		metaDataLen += len("; Expires=")
		// TODO: can we use fixed size here
		metaDataLen += len(c.Expires.Format(http.TimeFormat))
	}
	if c.MaxAge > 0 {
		metaDataLen += len("; Max-Age=")
		// TODO: use math solution
		metaDataLen += len(strconv.Itoa(c.MaxAge))
	} else if c.MaxAge < 0 {
		metaDataLen += len("; Max-Age=0")
	}
	if c.HttpOnly {
		metaDataLen += len("; HttpOnly")
	}
	if c.Secure {
		metaDataLen += len("; Secure")
	}
	switch c.SameSite {
	case http.SameSiteDefaultMode:
		// Skip, default mode is obtained by not emitting the attribute.
	case http.SameSiteNoneMode:
		metaDataLen += len("; SameSite=None")
	case http.SameSiteLaxMode:
		metaDataLen += len("; SameSite=Lax")
	case http.SameSiteStrictMode:
		metaDataLen += len("; SameSite=Strict")
	}
	return metaDataLen
}
