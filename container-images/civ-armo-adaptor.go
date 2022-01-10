package containerimages

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

type FeLoginData struct {
	Secret   string `json:"secret"`
	ClientId string `json:"clientId"`
}

type FeLoginResponse struct {
	Token        string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ExpiresIn    int32  `json:"expiresIn"`
	Expires      string `json:"expires"`
}

type ArmoCivAdaptor struct {
	registry  string
	accountId string
	clientId  string
	accessKey string
	feToken   FeLoginResponse
}

func CreateArmoAdaptor(registry string, credentials map[string]string) (*ArmoCivAdaptor, error) {
	var accountId string
	var accessKey string
	var clientId string
	var ok bool
	if accountId, ok = credentials["accountId"]; !ok {
		return nil, fmt.Errorf("Define accountId in credentials")
	}
	if clientId, ok = credentials["clientId"]; !ok {
		return nil, fmt.Errorf("Define clientId in credentials")
	}
	if accessKey, ok = credentials["accessKey"]; !ok {
		return nil, fmt.Errorf("Define accessKey in credentials")
	}
	return &ArmoCivAdaptor{registry: registry, accountId: accountId, clientId: clientId, accessKey: accessKey}, nil
}

func (armoCivAdaptor ArmoCivAdaptor) Login() error {
	feLoginData := FeLoginData{ClientId: armoCivAdaptor.clientId, Secret: armoCivAdaptor.accessKey}
	body, _ := json.Marshal(feLoginData)

	resp, err := http.Post("https://eggauth.eudev3.cyberarmorsoft.com/frontegg/identity/resources/auth/v1/api-token", "application/json", bytes.NewBuffer(body))
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		var feLoginResponse FeLoginResponse
		err = json.Unmarshal(body, &feLoginResponse)
		//fmt.Printf("Token: %s\n", feLoginResponse.Token)
		//fmt.Printf("Body: %s\n", string(body))
		if err != nil {
			return err
		}
	} else {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("Error authenticating: %d", resp.StatusCode)

		}
		return fmt.Errorf("Error authenticating: %d - %s", resp.StatusCode, string(body))
	}
	fmt.Printf("Success!")
	return nil
}
