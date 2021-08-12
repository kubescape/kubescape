package apis

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
)

// HTTPReqFunc allows you to insert query params and more to aggregation message while using update aggregator
type HTTPReqFunc func(req *http.Request, qryData interface{})

func BasicBEQuery(req *http.Request, qryData interface{}) {

	q := req.URL.Query()

	if notificationData, isok := qryData.(*LoginObject); isok {
		q.Add("customerGUID", notificationData.GUID)
	}

	req.URL.RawQuery = q.Encode()
}

func EmptyQuery(req *http.Request, qryData interface{}) {
	q := req.URL.Query()
	req.URL.RawQuery = q.Encode()
}

func MapQuery(req *http.Request, qryData interface{}) {
	q := req.URL.Query()
	if qryMap, isok := qryData.(map[string]string); isok {
		for k, v := range qryMap {
			q.Add(k, v)
		}

	}
	req.URL.RawQuery = q.Encode()
}

func BEHttpRequest(loginobj *LoginObject, beURL,
	httpverb string,
	endpoint string,
	payload []byte,
	f HTTPReqFunc,
	qryData interface{}) ([]byte, error) {
	client := &http.Client{}

	beURL = fmt.Sprintf("%v/%v", beURL, endpoint)
	req, err := http.NewRequest(httpverb, beURL, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", loginobj.Authorization)
	f(req, qryData)

	for _, cookie := range loginobj.Cookies {
		req.AddCookie(cookie)
	}
	resp, err := client.Do(req)
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

type BELoginResponse struct {
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
	Email             string `json:"email"`
	CustomerGuid      string `json:"customerGuid"`
	Expires           string `json:"expires"`
	Authorization     string `json:"authorization"`
	Cookies           []*http.Cookie
}

func (r *BELoginResponse) ToLoginObject() *LoginObject {
	l := &LoginObject{}
	l.Authorization = r.Authorization
	l.Cookies = r.Cookies
	l.Expires = r.Expires
	l.GUID = r.CustomerGuid

	return l
}

type BackendConnector struct {
	BaseURL         string
	BELoginResponse *BELoginResponse
	Credentials     *CustomerLoginDetails
	HTTPClient      *http.Client
}
