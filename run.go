package oidcproxy

import (
	"context"
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

var (
	version = "n/a"
	commit  = "n/a"
)

func Run() error {
	var (
		defaultProvider = ProviderConfig{}
		issuerURL       string
		clientID        string
		clientSecret    string
		callbackURL     string
		postLogoutURL   string
		scopes          string
		cookieHashKey   string
		cookieEncKey    string
		listenAddr      = "localhost:8080"
		tlsCert         string
		tlsKey          string
		upstream        string
		providerConfig  string
		showVersion     bool
	)

	// proxy options
	defaultScopes := []string{oidc.ScopeOpenID, "email", "profile", oidc.ScopeOfflineAccess}
	flag.StringVar(&defaultProvider.IssuerURL, "issuer-url", issuerURL, "oidc issuer url")
	flag.StringVar(&defaultProvider.ClientID, "client-id", clientID, "client id")
	flag.StringVar(&defaultProvider.ClientSecret, "client-secret", clientSecret, "client secret id")
	flag.StringVar(&scopes, "scopes", strings.Join(defaultScopes, ","), "a comma-seperated list of scopes")

	flag.StringVar(&callbackURL, "callback-url", callbackURL, "callback URL")
	flag.StringVar(&postLogoutURL, "post-logout-url", postLogoutURL, "post logout redirect uri")
	flag.StringVar(&cookieHashKey, "cookie-hash-key", cookieHashKey, "cookie hash key")
	flag.StringVar(&cookieEncKey, "cookie-enc-key", cookieEncKey, "cookie encryption key")
	flag.StringVar(&providerConfig, "provider-config", providerConfig, "provider config file")

	flag.StringVar(&upstream, "upstream", upstream, "url of the upsream. if not configured debug page is shown.")

	// server options
	flag.StringVar(&listenAddr, "addr", listenAddr, "listen address")
	flag.StringVar(&tlsCert, "tls-cert", tlsCert, "tls cert")
	flag.StringVar(&tlsKey, "tls-key", tlsKey, "tls key")

	flag.BoolVar(&showVersion, "version", false, "show version")

	err := readFlagFromEnv(flag.CommandLine, "OIDC_PROXY_")
	if err != nil {
		return err
	}

	flag.Parse()

	if showVersion {
		fmt.Printf("version=%s commit=%s\n", version, commit)
		os.Exit(0)
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))

	providers := []ProviderConfig{}
	if providerConfig != "" {
		providers, err = readProviders(providerConfig)
		if err != nil {
			return err
		}
	}

	if defaultProvider.ClientID != "" {
		defaultProvider.Scopes = strings.Split(scopes, ",")
		providers = append(providers, defaultProvider)
	}

	for i := range providers {
		providers[i].SetupSessionFunc = ChainSessionSetupFunc(SaveGroups()) //, RequireIDTokenGroup("B2BX_D3_ADMINAPI_ADMIN"))
	}

	if len(providers) == 0 {
		return fmt.Errorf("no configured providers")
	}

	for _, p := range providers {
		slog.Info("configured provider", "client_id", p.ClientID, "issuer_url", p.IssuerURL, "name", p.Name)
	}

	config := &Config{
		Providers: providers,

		AppName: "OIDC Proxy",

		CallbackURL:          callbackURL,
		PostLogoutRediretURI: postLogoutURL,

		LoginPath:       "/login",
		LogoutPath:      "/logout",
		DebugPath:       "/debug",
		RefreshPath:     "/refresh",
		SessionInfoPath: "/info",

		HashKey:    []byte(cookieHashKey),
		EncryptKey: []byte(cookieEncKey),
	}

	authenticator, err := NewAuthenticator(context.Background(), config)
	if err != nil {
		return err
	}

	var inner http.Handler
	if upstream != "" {
		inner, err = newForwardHandler(upstream)
		if err != nil {
			return err
		}
	} else {
		inner = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s := SessionFromContext(r.Context())
			if s.User != nil {
				fmt.Fprintln(w, "hello "+s.User.Name)
			} else {
				fmt.Fprintln(w, "hello")
			}
		})
	}

	authenticated := authenticator.Handler(inner)

	logger := newLogHandler(authenticated)

	if tlsCert != "" || tlsKey != "" {
		listenURL := fmt.Sprintf("https://%s/", listenAddr)
		slog.Info("run server", "addr", listenURL)
		return http.ListenAndServeTLS(listenAddr, tlsCert, tlsKey, logger)
	} else {
		listenURL := fmt.Sprintf("http://%s/", listenAddr)
		slog.Info("run server", "addr", listenURL)
		return http.ListenAndServe(listenAddr, logger)
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

func readProviders(file string) ([]ProviderConfig, error) {
	rawFile, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	providers := []ProviderConfig{}

	err = json.Unmarshal(rawFile, &providers)
	if err != nil {
		return nil, fmt.Errorf("failed to read providers: %w", err)
	}
	return providers, nil
}
