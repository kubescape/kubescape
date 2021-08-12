package apis

import "net/http"

// Connector - interface for any connector (BE/Portal and so on)
type Connector interface {

	//may used for a more generic httpsend interface based method
	GetBaseURL() string
	GetLoginObj() *LoginObject
	GetClient() *http.Client

	Login() error
	IsExpired() bool

	HTTPSend(httpverb string,
		endpoint string,
		payload []byte,
		f HTTPReqFunc,
		qryData interface{}) ([]byte, error)
}
