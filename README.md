# Distributed Encrypted Communication System

> Peer-to-peer encrypted messaging and file transfer between stations over TCP/UDP/WebSocket.

---

## Features

- Point-to-point encrypted messaging between 2–3 nodes
- Encrypted file transfer with splitting and reassembly
- AES symmetric encryption implemented from scratch per [FIPS 197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf)
- Diffie-Hellman key exchange
- No external cryptography libraries

## Stack

| Layer | Technology |
|---|---|
| Transport | TCP / UDP / WebSocket |
| Encryption | AES (FIPS 197) |
| Key Exchange | Diffie-Hellman |
| Language | Go |

## Project Structure

```
.
├── main.go
└── crypto/
    ├── aes.go   # AES interfaces (FIPS 197)
    └── dh.go    # Diffie-Hellman key exchange
```
