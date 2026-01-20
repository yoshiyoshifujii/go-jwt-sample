# go-jwt examples

Minimal examples for signing and verifying JWTs using github.com/golang-jwt/jwt/v5.

## Algorithms

- HS256: HMAC (shared secret)
- RS256: RSA (public/private key)
- PS256: RSA-PSS (public/private key)

## Files

- `jwt_interfaces.go`: signer/parser interfaces
- `hs256.go`: HS256 signer/parser
- `rs256.go`: RS256 signer/parser
- `ps256.go`: PS256 signer/parser
- `kms_ps256.go`: KMS-backed PS256 signer and public key fetcher
- `*_test.go`: tests for each algorithm

## Run

```bash
# run the HS256 example

go run .

# run tests

go test ./...

# run integration tests (requires Docker)

go test ./test/integration/...
```

## Notes

- The parsers verify the expected signing method before returning the key.
- RS256 and PS256 both use RSA keys; the difference is the padding scheme used during signing.

## Example

```go
signer := PS256Signer{PrivateKey: privateKey}
parser := PS256Parser{PublicKey: &privateKey.PublicKey}

token, err := signer.Sign(context.Background(), claims)
parsed, err := parser.Parse(context.Background(), token)
```

KMS example (PS256 with RSASSA_PSS_SHA_256):

```go
service := KMSService{Client: kmsClient, KeyID: "arn:aws:kms:..."}
signer := KMSPS256Signer{Service: service}
parser := KMSPS256Parser{Service: service}

token, err := signer.Sign(context.Background(), claims)
parsed, err := parser.Parse(context.Background(), token)
```
