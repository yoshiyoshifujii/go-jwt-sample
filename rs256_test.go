package gojwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestRS256SignParse(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	claims := jwt.MapClaims{
		"sub": "user-456",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Minute).Unix(),
	}

	signer := RS256Signer{PrivateKey: privateKey}
	parser := RS256Parser{PublicKey: &privateKey.PublicKey}

	signed, err := signer.Sign(context.Background(), claims)
	if err != nil {
		t.Fatalf("RS256Signer.Sign error: %v", err)
	}

	parsed, err := parser.Parse(context.Background(), signed)
	if err != nil {
		t.Fatalf("RS256Parser.Parse error: %v", err)
	}
	if !parsed.Valid {
		t.Fatalf("token should be valid")
	}
}
