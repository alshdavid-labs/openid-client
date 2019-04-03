package oidc

import (
	"fmt"
	"net/http"

	"gopkg.in/resty.v1"
)

func (p *Provider) sendTokenRequest(body map[string]string, result interface{}) error {
	body["client_id"] = p.ClientID
	body["client_secret"] = p.ClientSecret

	client := resty.DefaultClient
	client.DisableWarn = true
	resp, err := client.R().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		SetBasicAuth(p.ClientID, p.ClientSecret).
		SetResult(&result).
		SetFormData(body).
		Post(p.URLS.Token)

	if err != nil {
		return err
	}
	if resp.StatusCode() != http.StatusOK {
		return fmt.Errorf(OIDCErrors.HTTPError + string(resp.Body()))
	}
	return nil
}
