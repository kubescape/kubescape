package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetAndGetAccessKey(t *testing.T) {
	tests := []struct {
		name string
		key  string
	}{
		{
			name: "Non empty key",
			key:  "value1",
		},
		{
			name: "Empty key",
			key:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetAccessKey(tt.key)
			assert.Equal(t, tt.key, GetAccessKey())
		})
	}
}

func TestSetAndGetAccount(t *testing.T) {
	tests := []struct {
		name    string
		account string
	}{
		{
			name:    "Non empty account",
			account: "value1",
		},
		{
			name:    "Empty account",
			account: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetAccount(tt.account)
			assert.Equal(t, tt.account, GetAccount())
		})
	}
}
