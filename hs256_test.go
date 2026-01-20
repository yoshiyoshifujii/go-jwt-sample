package main

import (
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

	signed, err := SignHS256(secret, claims)
	if err != nil {
		t.Fatalf("SignHS256 error: %v", err)
	}

	parsed, err := ParseHS256(signed, secret)
	if err != nil {
		t.Fatalf("ParseHS256 error: %v", err)
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
