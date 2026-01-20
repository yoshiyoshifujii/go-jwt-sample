package gojwt

import (
	"context"

	"github.com/golang-jwt/jwt/v5"
)

type (
	JWTSigner interface {
		Sign(ctx context.Context, claims jwt.Claims) (string, error)
	}

	JWTParser interface {
		Parse(ctx context.Context, tokenString string) (*jwt.Token, error)
	}
)
