package oidc

import (
	"bytes"
	"net/url"
	"strings"
)

// Ripped from the offical OAuth2 package
func generateLoginURL(p *Provider, state string) string {
	var buf bytes.Buffer
	buf.WriteString(p.URLS.Auth)
	v := url.Values{
		"response_type": {"code"},
		"client_id":     {p.ClientID},
	}
	if p.RedirectURL != "" {
		v.Set("redirect_uri", p.RedirectURL)
	}
	if len(p.Scopes) > 0 {
		v.Set("scope", strings.Join(p.Scopes, " "))
	}
	if state != "" {
		v.Set("state", state)
	}
	if strings.Contains(p.URLS.Auth, "?") {
		buf.WriteByte('&')
	} else {
		buf.WriteByte('?')
	}
	buf.WriteString(v.Encode())
	return buf.String()
}
