package main

import (
	"context"
	"crypto/rsa"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

type (
	PS256Signer struct {
		PrivateKey *rsa.PrivateKey
	}

	PS256Parser struct {
		PublicKey *rsa.PublicKey
	}
)

func (s PS256Signer) Sign(_ context.Context, claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodPS256, claims)
	return token.SignedString(s.PrivateKey)
}

func (p PS256Parser) Parse(tokenString string) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodPS256 {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return p.PublicKey, nil
	})
}
