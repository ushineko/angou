//go:build e2e

package e2e

import (
	"encoding/base64"
	"encoding/hex"
)

func hexOf(b []byte) string    { return hex.EncodeToString(b) }
func base64Of(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
