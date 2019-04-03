package oidc

func refreshSession(p *Provider, refreshToken string) (*Session, error) {
	session := &Session{}
	err := p.sendTokenRequest(map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
	}, session)
	if err != nil {
		return nil, err
	}
	return session, nil
}
