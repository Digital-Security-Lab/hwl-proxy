package utils

import (
	"crypto/sha256"
	"fmt"
	"math/rand"
)

func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func GenerateRandomHash() string {
	randBytes, _ := GenerateRandomBytes(1000)
	sum := sha256.Sum256(randBytes)
	return fmt.Sprintf("%x", sum)
}

func GenerateRandomInt() int {
	return rand.Int()
}
