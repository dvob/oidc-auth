package testissuer

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetToken(t *testing.T) {
	config := NewDefaultConfig()

	config.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	iss, err := New(config)
	if err != nil {
		t.Fatal(err)
	}

	token, err := iss.GetToken(&AuthTokenInfo{
		ClientID: "myclient",
		User:     "test",
		Claims: map[string]any{
			"foo": "bar",
		},
	})
	require.NoError(t, err)

	claims, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[1])
	require.NoError(t, err)

	resultingClaims := map[string]any{}
	_ = json.Unmarshal(claims, &resultingClaims)

	require.Equal(t, resultingClaims["iss"], iss.IssuerURL)
	require.Equal(t, "bar", resultingClaims["foo"])
}
