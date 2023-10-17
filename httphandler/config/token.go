package config

var accessToken string
var accountId string

func SetAccessToken(token string) {
	accessToken = token
}

func GetAccessToken() string {
	return accessToken
}

func SetAccountId(id string) {
	accountId = id
}

func GetAccountId() string {
	return accountId
}
