package oidc

import (
	"crypto/rsa"

	"github.com/lestrrat-go/jwx/jwk"
	"gopkg.in/resty.v1"
)

func getPublicKey(set *jwk.Set) (*rsa.PublicKey, error) {
	publicKey, err := set.Keys[0].Materialize()
	if err != nil {
		return nil, err
	}
	return publicKey.(*rsa.PublicKey), nil
}

func fetchJWKSets(url string) (*jwk.Set, error) {
	resp, err := resty.R().Get(url)
	if err != nil {
		return nil, err
	}
	JWKValue := resp.String()
	sets, err := jwk.ParseString(JWKValue)
	if err != nil {
		return nil, err
	}
	return sets, nil
}
