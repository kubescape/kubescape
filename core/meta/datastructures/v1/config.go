package v1

import "io"

type SetConfig struct {
	Account   string
	ClientID  string
	SecretKey string
}

type ViewConfig struct {
	Writer io.Writer
}

type DeleteConfig struct {
}
