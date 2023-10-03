package config

var accessToken string

func SetAccessToken(token string) {
	accessToken = token
}

func GetAccessToken() string {
	return accessToken
}
