package oidc

// OIDCErrors are the error mappings for this package
// TODO: add more
var OIDCErrors = struct {
	SendTokenRequestFailure string
	HTTPError               string
}{
	HTTPError: "Errors.HTTPError",
}
