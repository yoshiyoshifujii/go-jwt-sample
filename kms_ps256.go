package gojwt

import (
	"context"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

type (
	KMSPS256Signer struct {
		Service KMSService
	}

	KMSPS256Parser struct {
		Service KMSService
	}
)

func (s KMSPS256Signer) Sign(ctx context.Context, claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodPS256, claims)
	sstr, err := token.SigningString()
	if err != nil {
		return "", err
	}

	sig, err := s.Service.SignRaw(ctx, []byte(sstr))
	if err != nil {
		return "", err
	}

	return sstr + "." + token.EncodeSegment(sig), nil
}

func (p KMSPS256Parser) Parse(ctx context.Context, tokenString string) (*jwt.Token, error) {
	publicKey, err := p.Service.FetchPublicKey(ctx)
	if err != nil {
		return nil, err
	}

	return jwt.Parse(tokenString, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodPS256 {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return publicKey, nil
	})
}
