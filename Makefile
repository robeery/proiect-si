.PHONY: build run test clean

build:
	go build ./...

run:
	go run main.go

test:
	go test ./tests/... -v

clean:
	go clean ./...
