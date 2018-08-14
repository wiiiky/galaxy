
.PHONY:galaxy

all: galaxy

galaxy:
	@go build -o bin/galaxy galaxy.go

fmt:
	@find . -name '*.go'|xargs gofmt -w

test:
	@go test ./...
