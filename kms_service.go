package gojwt

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type KMSService struct {
	Client *kms.Client
	KeyID  string
}

func (s KMSService) SignRaw(ctx context.Context, message []byte) ([]byte, error) {
	out, err := s.Client.Sign(ctx, &kms.SignInput{
		KeyId:            &s.KeyID,
		Message:          message,
		MessageType:      types.MessageTypeRaw,
		SigningAlgorithm: types.SigningAlgorithmSpecRsassaPssSha256,
	})
	if err != nil {
		return nil, err
	}

	return out.Signature, nil
}

// FetchPublicKey fetches the RSA public key for this KMS key.
func (s KMSService) FetchPublicKey(ctx context.Context) (*rsa.PublicKey, error) {
	out, err := s.Client.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: &s.KeyID})
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
