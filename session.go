package oidc

import (
	"time"
)

var timeNow = time.Now
var expiryDelta = 10 * time.Second

// Session describes the IDP response
type Session struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

// GetClaims will extracts the claims from the
// Session's IDToken. It will not validate the token
// so be sure to verify it against it's signature
// before trusting it
func (t *Session) GetClaims(i interface{}) {
	GetClaims(t.IDToken, i)
}

// GetExpiry will extract the expiry from the session's
// IDToken. It will not validate the token so be sure
// to verify it against it's signature before trusting it
func (t *Session) GetExpiry() time.Time {
	m := struct {
		Exp int64 `json:"exp"`
	}{}
	t.GetClaims(&m)
	return time.Unix(m.Exp, 0)
}

// FormatExpiry will return the expiry in UTC/ISO format
// It will not validate the token so be sure
// to verify it against it's signature before trusting it
func (t *Session) FormatExpiry() string {
	return t.GetExpiry().UTC().Format(time.RFC3339)
}

// ProcessTimeString will convert a UTC/ISO format string
// into a Go time struct, or die trying
func ProcessTimeString(t string) (time.Time, error) {
	layout := "2006-01-02T15:04:05Z07:00"
	return time.Parse(layout, t)
}
