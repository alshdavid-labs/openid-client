package oidc

func exchange(p *Provider, code string) (*Session, error) {
	session := &Session{}
	err := p.sendTokenRequest(map[string]string{
		"grant_type":   "authorization_code",
		"code":         code,
		"redirect_uri": p.RedirectURL,
	}, session)
	if err != nil {
		return nil, err
	}
	return session, nil
}
