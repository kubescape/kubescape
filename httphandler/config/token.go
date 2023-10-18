package config

var accessToken string
var account string

func SetAccessToken(token string) {
	accessToken = token
}

func GetAccessToken() string {
	return accessToken
}

func SetAccount(accountId string) {
	account = accountId
}

func GetAccount() string {
	return account
}
