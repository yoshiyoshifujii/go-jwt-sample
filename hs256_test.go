package main

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestHS256SignParse(t *testing.T) {
	secret := []byte("test-secret")
	claims := jwt.MapClaims{
		"sub": "user-123",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Minute).Unix(),
	}

	signer := HS256Signer{Secret: secret}
	parser := HS256Parser{Secret: secret}

	signed, err := signer.Sign(context.Background(), claims)
	if err != nil {
		t.Fatalf("HS256Signer.Sign error: %v", err)
	}

	parsed, err := parser.Parse(signed)
	if err != nil {
		t.Fatalf("HS256Parser.Parse error: %v", err)
	}
	if !parsed.Valid {
		t.Fatalf("token should be valid")
	}

	mapClaims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("claims should be MapClaims")
	}
	if mapClaims["sub"] != "user-123" {
		t.Fatalf("unexpected sub claim: %v", mapClaims["sub"])
	}
}
