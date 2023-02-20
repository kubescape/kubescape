package getter

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func GetDefaultPath(name string) string {
	return filepath.Join(DefaultLocalStore, name)
}

func SaveInFile(policy interface{}, pathStr string) error {
	encodedData, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return err
	}
	err = os.WriteFile(pathStr, encodedData, 0644) //nolint:gosec
	if err != nil {
		if os.IsNotExist(err) {
			pathDir := filepath.Dir(pathStr)
			// pathDir could contain subdirectories
			if erm := os.MkdirAll(pathDir, 0755); erm != nil {
				return erm
			}
		} else {
			return err

		}
		err = os.WriteFile(pathStr, encodedData, 0644) //nolint:gosec
		if err != nil {
			return err
		}
	}
	return nil
}

func HttpDelete(httpClient *http.Client, fullURL string, headers map[string]string) (string, error) {

	req, err := http.NewRequest("DELETE", fullURL, nil)
	if err != nil {
		return "", err
	}
	setHeaders(req, headers)

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

func HttpGetter(httpClient *http.Client, fullURL string, headers map[string]string) (string, error) {

	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return "", err
	}
	setHeaders(req, headers)

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

func HttpPost(httpClient *http.Client, fullURL string, headers map[string]string, body []byte) (string, error) {

	req, err := http.NewRequest("POST", fullURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	setHeaders(req, headers)
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

func setHeaders(req *http.Request, headers map[string]string) {
	if len(headers) >= 0 { // might be nil
		for k, v := range headers {
			req.Header.Set(k, v)
		}
	}
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
	_, err := io.Copy(&strBuilder, resp.Body)
	respStr := strBuilder.String()
	if err != nil {
		respStrNewLen := len(respStr)
		if respStrNewLen > 1024 {
			respStrNewLen = 1024
		}
		return "", fmt.Errorf("http-error: '%s', reason: '%s'", resp.Status, respStr[:respStrNewLen])
		// return "", fmt.Errorf("HTTP request failed. URL: '%s', Read-ERROR: '%s', HTTP-CODE: '%s', BODY(top): '%s', HTTP-HEADERS: %v, HTTP-BODY-BUFFER-LENGTH: %v", resp.Request.URL.RequestURI(), err, resp.Status, respStr[:respStrNewLen], resp.Header, bytesNum)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respStrNewLen := len(respStr)
		if respStrNewLen > 1024 {
			respStrNewLen = 1024
		}
		err = fmt.Errorf("http-error: '%s', reason: '%s'", resp.Status, respStr[:respStrNewLen])
	}

	return respStr, err
}
