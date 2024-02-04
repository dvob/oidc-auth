package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"

	"github.com/dvob/oidc-auth/testissuer"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {

	var (
		config = testissuer.NewDefaultConfig()
		addr   string
	)

	flag.StringVar(&config.IssuerURL, "issuer-url", config.IssuerURL, "the issuer url")
	flag.DurationVar(&config.TokenLifetime, "token-lifetime", config.TokenLifetime, "lifetime of the JWT tokens")
	flag.BoolVar(&config.AccessTokenIsJWT, "access-token-is-jwt", config.AccessTokenIsJWT, "access token will be a JWT token")
	flag.StringVar(&addr, "addr", addr, "the listen address. defaults to :<port> and port is taken from the issuer url.")

	flag.Parse()

	u, err := url.Parse(config.IssuerURL)
	if err != nil {
		return err
	}

	if addr == "" {
		port := u.Port()
		if port == "" {
			port = "80"
		}
		addr = ":" + port
	}

	issuer, err := testissuer.New(config)
	if err != nil {
		return err
	}

	handler := logHandler(issuer, slog.Default())

	err = http.ListenAndServe(addr, handler)
	if err != nil {
		return err
	}

	return nil
}
