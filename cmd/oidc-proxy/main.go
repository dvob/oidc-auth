package main

import (
	"fmt"
	"os"

	oidcproxy "github.com/dvob/oidc-proxy"
)

func main() {
	err := oidcproxy.Run()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
