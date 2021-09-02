package getter

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/armosec/kubescape/cautils/opapolicy"
)

func GetDefaultPath(frameworkName string) string {
	defaultfilePath := filepath.Join(DefaultLocalStore, frameworkName+".json")
	if homeDir, err := os.UserHomeDir(); err == nil {
		defaultfilePath = filepath.Join(homeDir, defaultfilePath)
	}
	return defaultfilePath
}

func SaveFrameworkInFile(framework *opapolicy.Framework, path string) error {
	encodedData, err := json.Marshal(framework)
	if err != nil {
		return err
	}
	err = os.WriteFile(path, []byte(fmt.Sprintf("%v", string(encodedData))), 0644)
	if err != nil {
		return err
	}
	return nil
}

// JSONDecoder returns JSON decoder for given string
func JSONDecoder(origin string) *json.Decoder {
	dec := json.NewDecoder(strings.NewReader(origin))
	dec.UseNumber()
	return dec
}

func HttpGetter(httpClient *http.Client, fullURL string) (string, error) {

	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	respStr, err := httpRespToString(resp)
	if err != nil {
		return "", err
	}
	return respStr, nil
}

// HTTPRespToString parses the body as string and checks the HTTP status code, it closes the body reader at the end
func httpRespToString(resp *http.Response) (string, error) {
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

// URLEncoder encode url
func urlEncoder(oldURL string) string {
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
