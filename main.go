package main

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

func main() {
	err := run()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	var (
		issuerURL    string
		clientID     string
		clientSecret string
		callbackURL  string
		scopes       string
		listenAddr   = "localhost:8080"
		tlsCert      string
		tlsKey       string
	)
	// proxy options
	defaultScopes := []string{oidc.ScopeOpenID, "email", "profile", oidc.ScopeOfflineAccess}
	flag.StringVar(&scopes, "scopes", strings.Join(defaultScopes, ","), "a comma-seperated list of scopes")
	flag.StringVar(&issuerURL, "issuer-url", issuerURL, "oidc issuer url")
	flag.StringVar(&clientID, "client-id", clientID, "client id")
	flag.StringVar(&clientSecret, "client-secret", clientSecret, "client secret id")
	flag.StringVar(&callbackURL, "callback-url", callbackURL, "callback URL")

	// server options
	flag.StringVar(&listenAddr, "addr", listenAddr, "listen address")
	flag.StringVar(&tlsCert, "tls-cert", tlsCert, "tls cert")
	flag.StringVar(&tlsKey, "tls-key", tlsKey, "tls key")

	err := readFlagFromEnv(flag.CommandLine, "OIDC_PROXY_")
	if err != nil {
		return err
	}
	flag.Parse()

	config := &OIDCProxyConfig{
		IssuerURL:    issuerURL,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       strings.Split(scopes, ","),
		CallbackURL:  callbackURL,
		LoginPath:    "/login",
		LogoutPath:   "/logout",
	}
	handler, err := NewOIDCProxyHandler(config, http.HandlerFunc(infoHandler))
	if err != nil {
		return err
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
	slog.Info("run server", "addr", listenAddr)
	if tlsCert != "" || tlsKey != "" {
		return http.ListenAndServeTLS(listenAddr, tlsCert, tlsKey, handler)
	} else {
		return http.ListenAndServe(listenAddr, handler)
	}
}

// readFlagFromEnv reads settings from environment into a FlagSet. This should
// be called after defining the flags and before flag.Parse. This way you have
// proper predence for the options.
//  1. flags
//  2. environment
//  3. defaults
func readFlagFromEnv(fs *flag.FlagSet, prefix string) error {
	errs := []error{}
	fs.VisitAll(func(f *flag.Flag) {
		envVarName := prefix + f.Name
		envVarName = strings.ReplaceAll(envVarName, "-", "_")
		envVarName = strings.ToUpper(envVarName)
		val, ok := os.LookupEnv(envVarName)
		if !ok {
			return
		}
		err := f.Value.Set(val)
		if err != nil {
			errs = append(errs, fmt.Errorf("invalid value '%s' in %s: %w", val, envVarName, err))
		}
	})
	return errors.Join(errs...)
}
