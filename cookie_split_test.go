package oidcproxy

import (
	"crypto/rand"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
)

func TestRemoveOldCookies(t *testing.T) {
	u, err := url.Parse("https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}

	cookieName := "mytest"

	myCookie := &http.Cookie{
		Name:   cookieName,
		Value:  randData(4100),
		Domain: "example.com",
	}

	applyCookie(t, jar, u, func(w http.ResponseWriter, r *http.Request) {
		SetCookie(w, r, myCookie)
	})

	if len(jar.Cookies(u)) != 2 {
		t.Fatal("expected two cookies for big value")
	}

	// Second request with small cookie
	myCookie.Value = "small value"

	applyCookie(t, jar, u, func(w http.ResponseWriter, r *http.Request) {
		SetCookie(w, r, myCookie)
	})

	if len(jar.Cookies(u)) != 1 {
		t.Fatal("cookie not removed")
	}
}

func TestSplit(t *testing.T) {

	for i, test := range []struct {
		data   string
		cookie *http.Cookie
	}{
		{
			data:   "",
			cookie: &http.Cookie{},
		},
		{
			data:   randData(1),
			cookie: &http.Cookie{},
		},
		{
			data:   randData(500),
			cookie: &http.Cookie{},
		},
		{
			data:   randData(4070),
			cookie: &http.Cookie{},
		},
		{
			data: randData(4070),
			cookie: &http.Cookie{
				Path:     "/",
				Domain:   "example.com",
				Secure:   true,
				HttpOnly: true,
			},
		},
		{
			data: randData(5000),
			cookie: &http.Cookie{
				Path:     "/",
				Domain:   "example.com",
				Secure:   true,
				HttpOnly: true,
			},
		},
	} {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			test := test
			u, err := url.Parse("https://example.com")
			if err != nil {
				t.Fatal(err)
			}
			jar, err := cookiejar.New(nil)
			if err != nil {
				t.Fatal(err)
			}

			cookieName := "mytest"

			test.cookie.Name = cookieName
			test.cookie.Value = test.data

			applyCookie(t, jar, u, func(w http.ResponseWriter, r *http.Request) {
				SetCookie(w, r, test.cookie)
			})

			var value string
			applyCookie(t, jar, u, func(w http.ResponseWriter, r *http.Request) {
				value, err = GetCookieValue(r, cookieName)
			})

			if value != test.data {
				t.Fatalf("values and data are not equal.\n value='%s'\n data ='%s'", value, test.data)
			}

		})
	}

}

func FuzzCookieSplit(f *testing.F) {
	f.Add("foo", "bar")
	f.Fuzz(func(t *testing.T, name, value string) {
		if len(name) > 100 {
			t.Skip()
		}
		cookie := &http.Cookie{
			Name:  name,
			Value: value,
		}

		cs := splitCookie(cookie)
		for _, c := range cs {
			out := c.String()
			if len(out) > MAX_COOKIE_SIZE {
				t.Fatalf("cookies=%d name=%q, value=%q, cookie_name=%q, cookie_value=%q, len=%d", len(cs), name, value, c.Name, out, len(out))
			}
		}
	})
}

func BenchmarkCookieSplit(b *testing.B) {
	cookie := &http.Cookie{
		Name:  "bench",
		Value: randData(5000),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = splitCookie(cookie)
	}
}

func applyCookie(t *testing.T, jar http.CookieJar, u *url.URL, handler http.HandlerFunc) {
	req := httptest.NewRequest("GET", u.String(), nil)

	for _, c := range jar.Cookies(req.URL) {
		req.AddCookie(c)
	}

	rec := httptest.NewRecorder()
	handler(rec, req)
	resp := rec.Result()
	for _, cookie := range resp.Header.Values("Set-Cookie") {
		if len(cookie) > MAX_COOKIE_SIZE {
			t.Fatalf("cookie too big '%s'", cookie)
		}
	}
	jar.SetCookies(req.URL, resp.Cookies())
}

func randData(n int) string {
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
