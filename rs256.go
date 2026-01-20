package main

import (
	"context"
	"crypto/rsa"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

type (
	RS256Signer struct {
		PrivateKey *rsa.PrivateKey
	}

	RS256Parser struct {
		PublicKey *rsa.PublicKey
	}
)

func (s RS256Signer) Sign(_ context.Context, claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(s.PrivateKey)
}

func (p RS256Parser) Parse(tokenString string) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodRS256 {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return p.PublicKey, nil
	})
}
