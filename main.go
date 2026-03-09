package main

import (
	"fmt"
	mycrypto "proiect-si/crypto"
)

func main() {
	// AES-128: 16-byte key
	key128 := []byte("thisisasecretkey") 
	aes128, err := mycrypto.NewAES(key128)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Printf("AES-128: key=%d bytes, rounds=%d, block=%d bytes\n",
		aes128.KeySize(), aes128.NumRounds(), aes128.BlockSize())

	roundKeys128, _ := aes128.ExpandKey(key128)
	fmt.Printf("Round keys generated: %d\n", len(roundKeys128))
	fmt.Printf("Round key 0 (= original key words): %x %x %x %x\n",
		roundKeys128[0][0], roundKeys128[0][1], roundKeys128[0][2], roundKeys128[0][3])
	fmt.Printf("Round key 1 (first derived):         %x %x %x %x\n",
		roundKeys128[1][0], roundKeys128[1][1], roundKeys128[1][2], roundKeys128[1][3])

	fmt.Println()

	// AES-256: 32-byte key
	key256 := []byte("thisisasecretkeyofthirtytwo!!!!!") 
	aes256, err := mycrypto.NewAES(key256)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Printf("AES-256: key=%d bytes, rounds=%d, block=%d bytes\n",
		aes256.KeySize(), aes256.NumRounds(), aes256.BlockSize())

	roundKeys256, _ := aes256.ExpandKey(key256)
	fmt.Printf("Round keys generated: %d\n", len(roundKeys256))

	fmt.Println()

	// Bad key size should return an error
	_, err = mycrypto.NewAES([]byte("shortkey"))
	fmt.Printf("Bad key error: %v\n", err)
}
