package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/golang-jwt/jwt/v5"
)

type KMSPS256Signer struct {
	Client *kms.Client
	KeyID  string
}

func (s KMSPS256Signer) Sign(ctx context.Context, claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodPS256, claims)
	signingString, err := token.SigningString()
	if err != nil {
		return "", err
	}

	out, err := s.Client.Sign(ctx, &kms.SignInput{
		KeyId:            &s.KeyID,
		Message:          []byte(signingString),
		MessageType:      types.MessageTypeRaw,
		SigningAlgorithm: types.SigningAlgorithmSpecRsassaPssSha256,
	})
	if err != nil {
		return "", err
	}

	signature := base64.RawURLEncoding.EncodeToString(out.Signature)
	return signingString + "." + signature, nil
}

// FetchKMSPS256PublicKey fetches the RSA public key to verify PS256 tokens.
func FetchKMSPS256PublicKey(ctx context.Context, client *kms.Client, keyID string) (*rsa.PublicKey, error) {
	out, err := client.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: &keyID})
	if err != nil {
		return nil, err
	}

	parsed, err := x509.ParsePKIXPublicKey(out.PublicKey)
	if err != nil {
		return nil, err
	}
	publicKey, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unexpected public key type: %T", parsed)
	}
	return publicKey, nil
}
