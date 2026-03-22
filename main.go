package main

import (
	"fmt"
	mycrypto "proiect-si/crypto"
)

func main() {
	// Uncomment one:
	//key := []byte("thisisasecretkey")                 // AES-128
	key := []byte("thisisasecretkeyofthirtytwo!!!!!") // AES-256

	var message string
	fmt.Print("Message (exactly 16 chars): ")
	fmt.Scanln(&message)

	plaintext := []byte(message)

	if len(key) != 16 && len(key) != 32 {
		fmt.Printf("Error: key must be 16 or 32 bytes, got %d\n", len(key))
		return
	}

	if len(plaintext) != 16 {
		fmt.Println("Error: message must be exactly 16 bytes (one AES block)")
		return
	}

	aes, err := mycrypto.NewAES(key)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// Encrypt
	ciphertext := make([]byte, 16)
	err = aes.Encrypt(ciphertext, plaintext)
	if err != nil {
		fmt.Println("Encrypt error:", err)
		return
	}
	if aes.KeySize() == 16 {
		fmt.Println("Mode: AES-128")
	} else {
		fmt.Println("Mode: AES-256")
	}
	fmt.Printf("Plaintext:  %s\n", plaintext)
	fmt.Printf("Ciphertext: %x\n", ciphertext)

	// Decrypt
	decrypted := make([]byte, 16)
	err = aes.Decrypt(decrypted, ciphertext)
	if err != nil {
		fmt.Println("Decrypt error:", err)
		return
	}
	fmt.Printf("Decrypted:  %s\n", decrypted)

	// Verify
	if string(decrypted) == string(plaintext) {
		fmt.Println("OK: decrypt(encrypt(msg)) == msg")
	} else {
		fmt.Println("FAIL: decrypted does not match original")
	}
}
