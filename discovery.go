package oidc

import (
	"fmt"
	"net/http"

	"gopkg.in/resty.v1"
)

func processDiscovery(url string) (URLS, string, error) {
	urls := URLS{
		URL:       url,
		Discovery: url + "/.well-known/openid-configuration",
	}

	var result map[string]interface{}
	resp, err := resty.R().
		SetResult(&result).
		Get(urls.Discovery)

	if resp.StatusCode() != http.StatusOK || err != nil {
		return urls, "", fmt.Errorf("ERROR: Unable to proccess discovery document")
	}

	urls.Auth = result["authorization_endpoint"].(string)
	urls.Token = result["token_endpoint"].(string)
	urls.JWK = result["jwks_uri"].(string)
	urls.EndSession = result["end_session_endpoint"].(string)
	issuer := result["issuer"].(string)
	return urls, issuer, nil
}
