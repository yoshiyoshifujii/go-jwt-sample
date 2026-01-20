.PHONY: test test-integration

test:
	go test $(shell go list ./... | rg -v '/test/')

test-integration:
	go test ./test/integration/...
