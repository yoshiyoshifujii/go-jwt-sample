package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/golang-jwt/jwt/v5"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	gojwt "go-jwt"
)

func TestKMSPS256SignParseLocalstack(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	req := testcontainers.ContainerRequest{
		Image:        "localstack/localstack:latest",
		ExposedPorts: []string{"4566/tcp"},
		Env:          map[string]string{"SERVICES": "kms"},
		WaitingFor:   wait.ForHTTP("/_localstack/health").WithPort("4566/tcp").WithStartupTimeout(2 * time.Minute),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("start localstack container: %v", err)
	}
	t.Cleanup(func() {
		_ = container.Terminate(context.Background())
	})

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("get localstack host: %v", err)
	}
	port, err := container.MappedPort(ctx, "4566/tcp")
	if err != nil {
		t.Fatalf("get localstack port: %v", err)
	}
	endpointURL := fmt.Sprintf("http://%s:%s", host, port.Port())

	cfg, err := config.LoadDefaultConfig(
		ctx,
		config.WithRegion("us-east-1"),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")),
	)
	if err != nil {
		t.Fatalf("load aws config: %v", err)
	}

	client := kms.NewFromConfig(cfg, func(o *kms.Options) {
		o.BaseEndpoint = aws.String(endpointURL)
	})
	keyOut, err := client.CreateKey(ctx, &kms.CreateKeyInput{
		KeyUsage: types.KeyUsageTypeSignVerify,
		KeySpec:  types.KeySpecRsa2048,
	})
	if err != nil {
		t.Fatalf("create kms key: %v", err)
	}
	if keyOut.KeyMetadata == nil || keyOut.KeyMetadata.KeyId == nil {
		t.Fatalf("kms key metadata missing")
	}
	keyID := *keyOut.KeyMetadata.KeyId

	claims := jwt.MapClaims{
		"sub": "user-999",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Minute).Unix(),
	}

	kmsService := gojwt.KMSService{Client: client, KeyID: keyID}
	signer := gojwt.KMSPS256Signer{Service: kmsService}
	parser := gojwt.KMSPS256Parser{Service: kmsService}

	signed, err := signer.Sign(ctx, claims)
	if err != nil {
		t.Fatalf("KMSPS256Signer.Sign error: %v", err)
	}

	parsed, err := parser.Parse(ctx, signed)
	if err != nil {
		t.Fatalf("KMSPS256Parser.Parse error: %v", err)
	}
	if !parsed.Valid {
		t.Fatalf("token should be valid")
	}
	if parsed.Method.Alg() != jwt.SigningMethodPS256.Alg() {
		t.Fatalf("unexpected alg: %s", parsed.Method.Alg())
	}

	mapClaims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("claims should be MapClaims")
	}
	if mapClaims["sub"] != "user-999" {
		t.Fatalf("unexpected sub claim: %v", fmt.Sprintf("%v", mapClaims["sub"]))
	}
}
