package policyhandler

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"kube-escape/cautils/opapolicy"
)

// URLEncoder encode url
func URLEncoder(oldURL string) string {
	fullURL := strings.Split(oldURL, "?")
	baseURL, err := url.Parse(fullURL[0])
	if err != nil {
		return ""
	}

	// Prepare Query Parameters
	if len(fullURL) > 1 {
		params := url.Values{}
		queryParams := strings.Split(fullURL[1], "&")
		for _, i := range queryParams {
			queryParam := strings.Split(i, "=")
			val := ""
			if len(queryParam) > 1 {
				val = queryParam[1]
			}
			params.Add(queryParam[0], val)
		}
		baseURL.RawQuery = params.Encode()
	}

	return baseURL.String()
}

type IArmoAPI interface {
	OPAFRAMEWORKGet(string) ([]opapolicy.Framework, error)
}

type ArmoAPI struct {
	httpClient *http.Client
	hostURL    string
}

func NewArmoAPI() *ArmoAPI {
	return &ArmoAPI{
		httpClient: &http.Client{},
		hostURL:    "https://dashbe.eudev3.cyberarmorsoft.com",
	}
}
func (db *ArmoAPI) GetServerAddress() string {
	return db.hostURL
}
func (db *ArmoAPI) GetHttpClient() *http.Client {
	return db.httpClient
}
func (db *ArmoAPI) OPAFRAMEWORKGet(name string) ([]opapolicy.Framework, error) {
	requestURI := "v1/armoFrameworks"
	requestURI += fmt.Sprintf("?customerGUID=%s", "11111111-1111-1111-1111-111111111111")
	requestURI += fmt.Sprintf("&frameworkName=%s", name)
	requestURI += "&getRules=true"

	fullURL := URLEncoder(fmt.Sprintf("%s/%s", db.GetServerAddress(), requestURI))
	frameworkList := []opapolicy.Framework{}

	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return frameworkList, err
	}
	c := http.Client{}
	resp, err := c.Do(req)
	if err != nil {
		return frameworkList, err
	}
	respStr, err := HTTPRespToString(resp)
	if err != nil {
		return frameworkList, err
	}
	if name != "" {
		frameworkSingle := opapolicy.Framework{}
		err = JSONDecoder(respStr).Decode(&frameworkSingle)
		frameworkList = append(frameworkList, frameworkSingle)
	} else {
		err = JSONDecoder(respStr).Decode(&frameworkList)
	}
	return frameworkList, err
}

// JSONDecoder returns JSON decoder for given string
func JSONDecoder(origin string) *json.Decoder {
	dec := json.NewDecoder(strings.NewReader(origin))
	dec.UseNumber()
	return dec
}

// HTTPRespToString parses the body as string and checks the HTTP status code, it closes the body reader at the end
func HTTPRespToString(resp *http.Response) (string, error) {
	if resp == nil || resp.Body == nil {
		return "", nil
	}
	strBuilder := strings.Builder{}
	defer resp.Body.Close()
	if resp.ContentLength > 0 {
		strBuilder.Grow(int(resp.ContentLength))
	}
	bytesNum, err := io.Copy(&strBuilder, resp.Body)
	respStr := strBuilder.String()
	if err != nil {
		respStrNewLen := len(respStr)
		if respStrNewLen > 1024 {
			respStrNewLen = 1024
		}
		return "", fmt.Errorf("HTTP request failed. URL: '%s', Read-ERROR: '%s', HTTP-CODE: '%s', BODY(top): '%s', HTTP-HEADERS: %v, HTTP-BODY-BUFFER-LENGTH: %v", resp.Request.URL.RequestURI(), err, resp.Status, respStr[:respStrNewLen], resp.Header, bytesNum)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respStrNewLen := len(respStr)
		if respStrNewLen > 1024 {
			respStrNewLen = 1024
		}
		err = fmt.Errorf("HTTP request failed. URL: '%s', HTTP-ERROR: '%s', BODY: '%s', HTTP-HEADERS: %v, HTTP-BODY-BUFFER-LENGTH: %v", resp.Request.URL.RequestURI(), resp.Status, respStr[:respStrNewLen], resp.Header, bytesNum)
	}

	return respStr, err
}

func (policyHandler *PolicyHandler) GetPoliciesFromBackend(notification *opapolicy.PolicyNotification) ([]opapolicy.Framework, error) {
	var errs error
	d := NewArmoAPI()
	frameworks := []opapolicy.Framework{}
	// Get - cacli opa get
	for _, rule := range notification.Rules {
		switch rule.Kind {
		case opapolicy.KindFramework:
			// backend
			receivedFrameworks, err := d.OPAFRAMEWORKGet(rule.Name)
			if err != nil {
				errs = fmt.Errorf("Could not download framework, please check if this framework exists")
			}
			frameworks = append(frameworks, receivedFrameworks...)

		default:
			err := fmt.Errorf("Missing rule kind, expected: %s", opapolicy.KindFramework)
			errs = fmt.Errorf("%s", err.Error())

		}
	}
	return frameworks, errs
}
