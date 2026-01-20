package main

import (
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

	signed, err := SignPS256(privateKey, claims)
	if err != nil {
		t.Fatalf("SignPS256 error: %v", err)
	}

	parsed, err := ParsePS256(signed, &privateKey.PublicKey)
	if err != nil {
		t.Fatalf("ParsePS256 error: %v", err)
	}
	if !parsed.Valid {
		t.Fatalf("token should be valid")
	}
}
