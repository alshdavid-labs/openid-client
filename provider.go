package oidc

import (
	"crypto/rsa"
	"fmt"
	"os"

	"github.com/lestrrat-go/jwx/jwk"
)

/*
	OAuth2 + OpenID Connect client
*/

// Provider defines an IDP
type Provider struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	URLS         URLS
	Set          *jwk.Set
	PublicKey    *rsa.PublicKey
}

// URLS are links to IDP service locations
// this is auto-populated using the discovery
// document during construction
type URLS struct {
	URL        string
	Token      string
	Auth       string
	Discovery  string
	JWK        string
	EndSession string
}

// NewProvider is the constructor for a Provider
func NewProvider(url, clientID, clientSecret string) *Provider {
	urls, issuer, _ := processDiscovery(url)
	set, _ := fetchJWKSets(urls.JWK)
	if set == nil {
		fmt.Println("Unable to get sets")
		os.Exit(1)
	}
	publicKey, _ := getPublicKey(set)
	if publicKey == nil {
		fmt.Println("Failed to get public keys")
		os.Exit(1)
	}

	return &Provider{
		Issuer:       issuer,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       []string{"openid", "offline_access"},
		URLS:         urls,
		Set:          set,
		PublicKey:    publicKey,
	}
}

// WithScopes is a convenience method to use inline
// during the creation of a Provider
func (p *Provider) WithScopes(scopes ...string) *Provider {
	p.AddScopes(scopes...)
	return p
}

// AddScopes allows you to append scopes to a Provider's
// existing scopes
func (p *Provider) AddScopes(scopes ...string) {
	p.Scopes = append(p.Scopes, scopes...)
}

// GenerateLoginURL is used to create the URL
// an http server will redirect to when authenticating
func (p *Provider) GenerateLoginURL(state string) string {
	return generateLoginURL(p, state)
}

// Exchange is used to exchange a code from the IDP
// returning a Session (which contains your tokens)
func (p *Provider) Exchange(code string) (*Session, error) {
	return exchange(p, code)
}

// VerifyTokens checks the validity of tokens
func (p *Provider) VerifyTokens(tokens ...string) error {
	return verifyTokens(p, tokens...)
}

// RefreshSession will generate a new Session using a
// supplied refresh_token
func (p *Provider) RefreshSession(refreshToken string) (*Session, error) {
	return refreshSession(p, refreshToken)
}

// GenerateLogoutURL will supply a URL to navigate to
// to do a logout action
func (p *Provider) GenerateLogoutURL(session *Session, returnURL string) string {
	return logout(p, session, returnURL)
}
