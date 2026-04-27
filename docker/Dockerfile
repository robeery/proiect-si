# stage 1: build
FROM golang:alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o peer .

# stage 2: minimal runtime image
FROM alpine:latest

RUN adduser -D peer
USER peer
WORKDIR /home/peer

COPY --from=builder /src/peer ./peer

ENTRYPOINT ["./peer"]
