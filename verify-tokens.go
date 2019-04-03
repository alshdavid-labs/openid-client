package oidc

import (
	"fmt"

	"github.com/dgrijalva/jwt-go"
)

var expiredTokenError = "Token is expired"

// ErrorsVerification is a constant value for
// exported error messages
var ErrorsVerification = struct {
	TokenExpired string
}{
	TokenExpired: "Errors.Verification.TokenExpired",
}

func verifyTokens(p *Provider, tokens ...string) error {
	for _, token := range tokens {
		_, err := jwt.Parse(token, func(*jwt.Token) (interface{}, error) {
			return p.PublicKey, nil
		})
		if err == nil {
			continue
		}
		if err.Error() == expiredTokenError {
			return fmt.Errorf(ErrorsVerification.TokenExpired)
		}
		return err
	}
	return nil
}
