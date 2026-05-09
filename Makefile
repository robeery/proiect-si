.PHONY: build run test clean

build:
	go build -o peer .

run:
	go run .

test:
	go test ./tests/... -timeout 120s -v

clean:
	go clean ./...
	rm -f peer