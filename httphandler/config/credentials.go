package config

var accessKey string
var account string

func SetAccessKey(key string) {
	accessKey = key
}

func GetAccessKey() string {
	return accessKey
}

func SetAccount(accountId string) {
	account = accountId
}

func GetAccount() string {
	return account
}
