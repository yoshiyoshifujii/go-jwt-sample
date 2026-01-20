package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestPS256SignParse(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	claims := jwt.MapClaims{
		"sub": "user-789",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Minute).Unix(),
	}

	signer := PS256Signer{PrivateKey: privateKey}
	parser := PS256Parser{PublicKey: &privateKey.PublicKey}

	signed, err := signer.Sign(context.Background(), claims)
	if err != nil {
		t.Fatalf("PS256Signer.Sign error: %v", err)
	}

	parsed, err := parser.Parse(signed)
	if err != nil {
		t.Fatalf("PS256Parser.Parse error: %v", err)
	}
	if !parsed.Valid {
		t.Fatalf("token should be valid")
	}
}
