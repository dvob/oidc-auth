package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	oidcauth "github.com/dvob/oidc-auth"
)

func main() {
	err := run()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var (
	version = "n/a"
	commit  = "n/a"
)

func run() error {
	var (
		defaultProvider    = oidcauth.ProviderConfig{}
		scopes             string
		providerConfig     string
		config             = oidcauth.NewDefaultConfig()
		cookieHashKey      string
		cookieEncKey       string
		cookieRandKeys     bool
		listenAddr         = "localhost:8080"
		tlsCert            string
		tlsKey             string
		upstream           string
		useIDToken         bool
		enableDebugHandler bool
		showVersion        bool
	)

	// proxy options
	flag.StringVar(&defaultProvider.IssuerURL, "issuer-url", defaultProvider.IssuerURL, "oidc issuer url")
	flag.StringVar(&defaultProvider.ClientID, "client-id", defaultProvider.ClientID, "client id")
	flag.StringVar(&defaultProvider.ClientSecret, "client-secret", defaultProvider.ClientSecret, "client secret id")
	defaultScopes := []string{"openid", "email", "profile", "offline_access"}
	flag.StringVar(&scopes, "scopes", strings.Join(defaultScopes, ","), "a comma-seperated list of scopes")

	flag.StringVar(&providerConfig, "provider-config", providerConfig, "provider config file")

	flag.StringVar(&config.CallbackURL, "callback-url", config.CallbackURL, "callback URL")
	flag.StringVar(&config.PostLogoutRediretURI, "post-logout-url", config.PostLogoutRediretURI, "post logout redirect uri")
	flag.StringVar(&cookieHashKey, "cookie-hash-key", cookieHashKey, "cookie hash key")
	flag.StringVar(&cookieEncKey, "cookie-enc-key", cookieEncKey, "cookie encryption key")
	flag.BoolVar(&cookieRandKeys, "cookie-rand-keys", cookieRandKeys, "use a random key for cookie encryption and hash")
	flag.BoolVar(&config.CookieConfig.Secure, "cookie-secure", config.CookieConfig.Secure, "set cookie secure setting")

	flag.BoolVar(&enableDebugHandler, "enable-debug-handler", enableDebugHandler, "enable debug handler under /debug which shows actual tokens")

	flag.StringVar(&config.TemplateDir, "template-dir", config.TemplateDir, "template dir to overwrite existing templates")
	flag.BoolVar(&config.TemplateDevMode, "template-dev-mode", config.TemplateDevMode, "reload templates on each request")
	flag.StringVar(&config.AppName, "app-name", config.AppName, "app name to show on the provider selection login screen")

	flag.StringVar(&upstream, "upstream", upstream, "url of the upsream. if not configured debug page is shown.")
	flag.BoolVar(&useIDToken, "use-id-token", useIDToken, "send the id token to the upstream server")

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

	providers := []oidcauth.ProviderConfig{}
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
		providers[i].SetupSessionFunc = oidcauth.ChainSessionSetupFunc(oidcauth.SaveGroups())
	}

	if len(providers) == 0 {
		return fmt.Errorf("no configured providers")
	}

	for _, p := range providers {
		slog.Info("configured provider", "client_id", p.ClientID, "issuer_url", p.IssuerURL, "name", p.Name)
	}

	if cookieHashKey == "" && cookieRandKeys {
		randBytes := make([]byte, 32)
		_, err := rand.Read(randBytes)
		if err != nil {
			panic(err)
		}
		cookieHashKey = string(randBytes)
	}

	if cookieEncKey == "" && cookieRandKeys {
		randBytes := make([]byte, 32)
		_, err := rand.Read(randBytes)
		if err != nil {
			panic(err)
		}
		cookieEncKey = string(randBytes)
	}

	config.HashKey = []byte(cookieHashKey)
	config.EncryptionKey = []byte(cookieEncKey)
	config.Providers = providers

	ctx := context.Background()

	oidcAuth, err := oidcauth.NewAuthenticator(ctx, config)
	if err != nil {
		return err
	}

	debugHandler := oidcauth.DebugHandler(oidcAuth.SessionManager, oidcAuth.Providers)

	var proxy http.Handler
	if upstream != "" {
		proxy, err = newForwardHandler(upstream, useIDToken, nil)
		if err != nil {
			return err
		}
	} else {
		if enableDebugHandler {
			proxy = debugHandler
		} else {
			proxy = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				s := oidcauth.SessionFromContext(r.Context())
				if s.User != nil {
					fmt.Fprintln(w, "hello "+s.User.Name)
				} else {
					fmt.Fprintln(w, "hello")
				}
			})
		}
	}

	authenticated := oidcAuth.FullMiddleware(proxy)

	if enableDebugHandler {
		authenticated.Handle("/auth/debug", debugHandler)
	}

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

func readProviders(file string) ([]oidcauth.ProviderConfig, error) {
	rawFile, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	providers := []oidcauth.ProviderConfig{}

	err = json.Unmarshal(rawFile, &providers)
	if err != nil {
		return nil, fmt.Errorf("failed to read providers: %w", err)
	}
	return providers, nil
}
