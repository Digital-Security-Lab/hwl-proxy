package utils_test

import (
	"testing"

	"github.com/digital-security-lab/hwl-proxy/utils"
)

func TestGenerateRandomBytes(t *testing.T) {
	result, err := utils.GenerateRandomBytes(10)
	if err != nil {
		t.Error("Error is not nil")
	}
	if len(result) != 10 {
		t.Error("Byte length not correct")
	}
}

func TestGenerateRandomString(t *testing.T) {
	hash := utils.GenerateRandomHash()
	if len(hash) == 0 {
		t.Error("Hash string is empty")
	}
}

func TestGenerateRandomInt(t *testing.T) {
	utils.GenerateRandomInt()
}
