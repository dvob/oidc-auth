package main

import (
	"encoding/json"
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

type Provider struct {
	IssuerURL    string   `json:"issuer_url"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	Scopes       []string `json:"scopes"`

	Name string `json:"name"`
}

type Config struct {
	Providers map[string]Provider
}

func run() error {
	var (
		defaultProvider = Provider{}
		issuerURL       string
		clientID        string
		clientSecret    string
		callbackURL     string
		scopes          string
		cookieHashKey   string
		cookieEncKey    string
		listenAddr      = "localhost:8080"
		tlsCert         string
		tlsKey          string
		providerConfig  string
	)

	// proxy options
	defaultScopes := []string{oidc.ScopeOpenID, "email", "profile", oidc.ScopeOfflineAccess}
	flag.StringVar(&defaultProvider.IssuerURL, "issuer-url", issuerURL, "oidc issuer url")
	flag.StringVar(&defaultProvider.ClientID, "client-id", clientID, "client id")
	flag.StringVar(&defaultProvider.ClientSecret, "client-secret", clientSecret, "client secret id")
	flag.StringVar(&scopes, "scopes", strings.Join(defaultScopes, ","), "a comma-seperated list of scopes")

	flag.StringVar(&callbackURL, "callback-url", callbackURL, "callback URL")
	flag.StringVar(&cookieHashKey, "cookie-hash-key", cookieHashKey, "cookie hash key")
	flag.StringVar(&cookieEncKey, "cookie-enc-key", cookieEncKey, "cookie encryption key")
	flag.StringVar(&providerConfig, "provider-config", providerConfig, "provider config file")

	// server options
	flag.StringVar(&listenAddr, "addr", listenAddr, "listen address")
	flag.StringVar(&tlsCert, "tls-cert", tlsCert, "tls cert")
	flag.StringVar(&tlsKey, "tls-key", tlsKey, "tls key")

	err := readFlagFromEnv(flag.CommandLine, "OIDC_PROXY_")
	if err != nil {
		return err
	}

	flag.Parse()
	defaultProvider.Scopes = strings.Split(scopes, ",")

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))

	// TODO: we can do better
	var providers map[string]Provider
	if providerConfig != "" {
		providers, err = readProviders(providerConfig)
		if err != nil {
			return err
		}
	}
	if providers == nil {
		providers = make(map[string]Provider)
	}

	if defaultProvider.ClientID != "" {
		providers["default"] = defaultProvider
	}

	if len(providers) == 0 {
		return fmt.Errorf("no configured providers")
	}

	for name, provider := range providers {
		if provider.Name != "" {
			name = fmt.Sprintf("%s (%s)", name, provider.Name)
		}
		slog.Info("configured provider", "name", name, "issuer_url", provider.IssuerURL)
	}

	config := &OIDCProxyConfig{
		Providers: providers,

		CallbackURL: callbackURL,

		LoginPath:  "/login",
		LogoutPath: "/logout",

		HashKey:    []byte(cookieHashKey),
		EncryptKey: []byte(cookieEncKey),
	}
	handler, err := NewOIDCProxyHandler(config, http.HandlerFunc(infoHandler))
	if err != nil {
		return err
	}

	if tlsCert != "" || tlsKey != "" {
		listenURL := fmt.Sprintf("https://%s/", listenAddr)
		slog.Info("run server", "addr", listenURL)
		return http.ListenAndServeTLS(listenAddr, tlsCert, tlsKey, handler)
	} else {
		listenURL := fmt.Sprintf("http://%s/", listenAddr)
		slog.Info("run server", "addr", listenURL)
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

func readProviders(file string) (map[string]Provider, error) {
	rawFile, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	providers := map[string]Provider{}

	err = json.Unmarshal(rawFile, &providers)
	if err != nil {
		return nil, err
	}
	return providers, nil
}
