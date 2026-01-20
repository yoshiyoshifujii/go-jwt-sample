# go-jwt examples

Minimal examples for signing and verifying JWTs using github.com/golang-jwt/jwt/v5.

## Algorithms

- HS256: HMAC (shared secret)
- RS256: RSA (public/private key)
- PS256: RSA-PSS (public/private key)

## Files

- `hs256.go`: HS256 sign/parse helpers
- `rs256.go`: RS256 sign/parse helpers
- `ps256.go`: PS256 sign/parse helpers
- `*_test.go`: tests for each algorithm

## Run

```bash
# run the HS256 example

go run .

# run tests

go test ./...
```

## Notes

- The Parse helpers verify the expected signing method before returning the key.
- RS256 and PS256 both use RSA keys; the difference is the padding scheme used during signing.
