package main

import (
	"context"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

type (
	HS256Signer struct {
		Secret []byte
	}

	HS256Parser struct {
		Secret []byte
	}
)

func (s HS256Signer) Sign(_ context.Context, claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.Secret)
}

func (p HS256Parser) Parse(tokenString string) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return p.Secret, nil
	})
}
