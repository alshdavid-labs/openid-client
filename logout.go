package oidc

func logout(p *Provider, s *Session, returnURL string) string {
	return p.URLS.EndSession + "?id_token_hint=" + s.IDToken + "&post_logout_redirect_uri=" + returnURL
}
