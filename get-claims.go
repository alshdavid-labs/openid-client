package oidc

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

/*
	WARNING: Only use this function if you have previously
	validated the JWT
*/

// GetClaims is a utility that extracts claims from a token
// without validating it's signature
func GetClaims(token string, i interface{}) {
	b64 := strings.Split(token, ".")[1]
	unpackedJWT, _ := base64.RawStdEncoding.DecodeString(b64)
	json.Unmarshal(unpackedJWT, i)
}
