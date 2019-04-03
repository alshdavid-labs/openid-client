package oidc

import (
	"fmt"
	"net/http"
	"net/url"
	"time"
)

/*
	Helpers for integration into Go's standard HTTP package
*/

// AddSessionToCookie will unpack the session into a cookie
func AddSessionToCookie(w http.ResponseWriter, s *Session) {
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    s.AccessToken,
		HttpOnly: true,
		Path:     "/",
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "id_token",
		Value:    s.IDToken,
		HttpOnly: true,
		Path:     "/oauth",
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    s.RefreshToken,
		HttpOnly: true,
		Path:     "/oauth",
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "token_type",
		Value:    s.TokenType,
		HttpOnly: true,
		Path:     "/oauth",
	})
}

// GetSessionFromCookie will get the session from the cookie
// and cast it to a Session struct
func GetSessionFromCookie(r *http.Request) (*Session, error) {
	s := &Session{
		AccessToken:  getCookie(r, "access_token"),
		IDToken:      getCookie(r, "id_token"),
		RefreshToken: getCookie(r, "refresh_token"),
		TokenType:    getCookie(r, "token_type"),
	}
	if s.AccessToken == "" ||
		s.IDToken == "" ||
		s.RefreshToken == "" ||
		s.TokenType == "" {
		return nil, fmt.Errorf("SessionCookieValidationError")
	}
	return s, nil
}

// DeleteSessionFromCookie will remove the session from the cookie
func DeleteSessionFromCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    "",
		HttpOnly: true,
		Path:     "/",
		Expires:  time.Unix(0, 0),
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "id_token",
		Value:    "",
		HttpOnly: true,
		Path:     "/oauth",
		Expires:  time.Unix(0, 0),
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		HttpOnly: true,
		Path:     "/oauth",
		Expires:  time.Unix(0, 0),
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "token_type",
		Value:    "",
		HttpOnly: true,
		Path:     "/oauth",
		Expires:  time.Unix(0, 0),
	})
}

func getCookie(r *http.Request, name string) string {
	cookie, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	val, _ := url.QueryUnescape(cookie.Value)
	return val
}
