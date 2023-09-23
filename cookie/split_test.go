package cookie

import (
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRemoveOldCookies(t *testing.T) {
	cookieName := "mytest"

	myCookie := &http.Cookie{
		Name:   cookieName,
		Value:  randString(4100),
		Domain: "example.com",
	}

	// First Request with big cookie
	rec := httptest.NewRecorder()
	SetCookie(rec, &http.Request{}, myCookie)
	resp := rec.Result()

	req := responseIntoRequest(resp)

	cs := getCookies(req, cookieName)
	if len(cs) != 2 {
		t.Fatal("expected two cookies for big value")
	}

	// Second request with small cookie
	myCookie.Value = "small value"

	rec = httptest.NewRecorder()
	SetCookie(rec, req, myCookie)
	resp = rec.Result()

	req = responseIntoRequest(resp)

	cs = getCookies(req, cookieName)
	if len(cs) != 1 {
		t.Fatal("no longer used cookie got not deleted")
	}
}

func TestSplit(t *testing.T) {
	data := randString(4100)
	cookieName := "mytest"

	myCookie := &http.Cookie{
		Name:   cookieName,
		Value:  data,
		Domain: "example.com",
	}

	rec := httptest.NewRecorder()
	SetCookie(rec, &http.Request{}, myCookie)
	resp := rec.Result()

	req := responseIntoRequest(resp)

	value, _ := GetCookieValue(req, cookieName)

	if value != data {
		t.Fatalf("values and data are not equal.\n value='%s'\n data ='%s'", value, data)
	}
}

func randString(n int) string {
	const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	r := make([]byte, n)
	_, err := rand.Read(r)
	if err != nil {
		panic(err)
	}

	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[int(r[i])%len(letterBytes)]
	}
	return string(b)
}

func responseIntoRequest(resp *http.Response) *http.Request {
	req := &http.Request{
		Header: make(http.Header),
	}
	newCookies := []string{}
	for _, c := range resp.Cookies() {
		if c.MaxAge < 0 || (!c.Expires.IsZero() && time.Now().After(c.Expires)) {
			continue
		}
		newC := &http.Cookie{
			Name:  c.Name,
			Value: c.Value,
		}
		newCookies = append(newCookies, newC.String())
	}
	req.Header["Cookie"] = newCookies
	return req
}
