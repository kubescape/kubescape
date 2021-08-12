package apis

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

func MakeBackendConnector(client *http.Client, baseURL string, loginDetails *CustomerLoginDetails) (*BackendConnector, error) {
	if err := ValidateBEConnectorMakerInput(client, baseURL, loginDetails); err != nil {
		return nil, err
	}
	conn := &BackendConnector{BaseURL: baseURL, Credentials: loginDetails, HTTPClient: client}
	err := conn.Login()

	return conn, err
}

func ValidateBEConnectorMakerInput(client *http.Client, baseURL string, loginDetails *CustomerLoginDetails) error {
	if client == nil {
		fmt.Errorf("You must provide an initialized httpclient")
	}
	if len(baseURL) == 0 {
		return fmt.Errorf("you must provide a valid backend url")
	}

	if loginDetails == nil || (len(loginDetails.Email) == 0 && len(loginDetails.Password) == 0) {
		return fmt.Errorf("you must provide valid login details")
	}
	return nil

}

func (r *BackendConnector) Login() error {
	if !r.IsExpired() {
		return nil
	}

	loginInfoBytes, err := json.Marshal(r.Credentials)
	if err != nil {
		return fmt.Errorf("unable to marshal credentials properly")
	}

	beURL := fmt.Sprintf("%v/%v", r.BaseURL, "login")

	req, err := http.NewRequest("POST", beURL, bytes.NewReader(loginInfoBytes))
	if err != nil {
		return err
	}

	req.Header.Set("Referer", strings.Replace(beURL, "dashbe", "cpanel", 1))
	resp, err := r.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("unable to read login response")
	}

	loginS := &BELoginResponse{}
	json.Unmarshal(body, &loginS)

	loginS.Cookies = resp.Cookies()
	r.BELoginResponse = loginS

	return nil
}

func (r *BackendConnector) IsExpired() bool {
	return r.BELoginResponse == nil || r.BELoginResponse.ToLoginObject().IsExpired()
}

func (r *BackendConnector) GetBaseURL() string {
	return r.BaseURL
}
func (r *BackendConnector) GetLoginObj() *LoginObject {
	return r.BELoginResponse.ToLoginObject()
}
func (r *BackendConnector) GetClient() *http.Client {
	return r.HTTPClient
}

func (r *BackendConnector) HTTPSend(httpverb string,
	endpoint string,
	payload []byte,
	f HTTPReqFunc,
	qryData interface{}) ([]byte, error) {

	beURL := fmt.Sprintf("%v/%v", r.GetBaseURL(), endpoint)
	req, err := http.NewRequest(httpverb, beURL, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}

	if r.IsExpired() {
		r.Login()
	}

	loginobj := r.GetLoginObj()
	req.Header.Set("Authorization", loginobj.Authorization)
	f(req, qryData)
	q := req.URL.Query()
	q.Set("customerGUID", loginobj.GUID)
	req.URL.RawQuery = q.Encode()

	for _, cookie := range loginobj.Cookies {
		req.AddCookie(cookie)
	}
	resp, err := r.GetClient().Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fmt.Printf("req:\n%v\nresp:%v\n", req, resp)
		return nil, fmt.Errorf("Error #%v Due to: %v", resp.StatusCode, resp.Status)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}
