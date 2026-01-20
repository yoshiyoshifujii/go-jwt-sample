.PHONY: test test-integration

test:
	go test -count=1 $(shell go list ./... | rg -v '/test/')

test-integration:
	go test -count=1 ./test/integration/...
