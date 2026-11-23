package config

import "sync"

var (
	credMu    sync.RWMutex
	accessKey string
	account   string
)

func SetAccessKey(key string) {
	credMu.Lock()
	defer credMu.Unlock()
	accessKey = key
}

func GetAccessKey() string {
	credMu.RLock()
	defer credMu.RUnlock()
	return accessKey
}

func SetAccount(accountId string) {
	credMu.Lock()
	defer credMu.Unlock()
	account = accountId
}

func GetAccount() string {
	credMu.RLock()
	defer credMu.RUnlock()
	return account
}
