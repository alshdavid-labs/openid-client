package oidc

import (
	"strings"

	"github.com/qkgo/obfuscate"
)

// GetURLFromState is used to decode a state string,
// extract its values and create a query string of the
// items in the state
func GetURLFromState(encodedState string, baseHref string) (returnURL string) {
	var decoded map[string]string
	obfuscate.Decode(encodedState, &decoded)
	returnURL = decoded["returnUrl"]

	if returnURL == "" {
		returnURL = baseHref + "/session"
	}

	if strings.HasPrefix(returnURL, "http") {
		return ""
	}

	return returnURL
}
