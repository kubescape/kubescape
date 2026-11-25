package config

import (
	"fmt"
	"sync"
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

func TestCredentialsConcurrentAccess(t *testing.T) {
	origAccessKey, origAccount := GetAccessKey(), GetAccount()
	defer func() {
		SetAccessKey(origAccessKey)
		SetAccount(origAccount)
	}()

	var wg sync.WaitGroup
	for range 10 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := range 100 {
				SetAccessKey(fmt.Sprintf("key-%d", j))
				SetAccount(fmt.Sprintf("acc-%d", j))
			}
		}()
		go func() {
			defer wg.Done()
			for range 100 {
				_ = GetAccessKey()
				_ = GetAccount()
			}
		}()
	}
	wg.Wait()
}
