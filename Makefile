.PHONY: build run listen dial test clean

build:
	go build -o peer .

listen:
	go run . listen --port 9001

dial:
	go run . dial --peer 127.0.0.1:9001

test:
	go test ./tests/... -timeout 120s -v

clean:
	go clean ./...
	rm -f peer
