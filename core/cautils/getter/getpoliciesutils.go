package getter

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const savedJSONFileMode os.FileMode = 0o644

var renameSavedFile = os.Rename

// GetDefaultPath returns a location under the local dot files for kubescape.
//
// This is typically located under $HOME/.kubescape
func GetDefaultPath(name string) string {
	return filepath.Join(DefaultLocalStore, name)
}

// PolicyCacheFilename returns the canonical cache filename for a framework or control identifier.
func PolicyCacheFilename(identifier string) (string, error) {
	norm := strings.ToLower(strings.TrimSpace(identifier))
	if norm == "" {
		return "", fmt.Errorf("policy identifier is empty")
	}
	if norm == "." || norm == ".." || strings.ContainsAny(norm, `/\`) {
		return "", fmt.Errorf("policy identifier contains path separators")
	}
	return norm + ".json", nil
}

// PolicyCachePath returns the canonical cache file path under the local kubescape store for a framework or control identifier.
func PolicyCachePath(identifier string) (string, error) {
	name, err := PolicyCacheFilename(identifier)
	if err != nil {
		return "", err
	}
	return GetDefaultPath(name), nil
}

// SaveInFile serializes any object as a JSON file.
func SaveInFile(object any, targetFile string) error {
	encodedData, err := json.MarshalIndent(object, "", "  ")
	if err != nil {
		return err
	}
	if targetFile == "" {
		return fmt.Errorf("target file is empty")
	}

	targetDir := filepath.Dir(targetFile)
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return fmt.Errorf("create target directory: %w", err)
	}

	mode, err := savedFileMode(targetFile)
	if err != nil {
		return err
	}

	tempFile, err := os.CreateTemp(targetDir, ".kubescape-json-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary JSON file: %w", err)
	}
	tempPath := tempFile.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tempPath)
		}
	}()

	if err := tempFile.Chmod(mode); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("set temporary JSON file permissions: %w", err)
	}
	if _, err := tempFile.Write(encodedData); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("write temporary JSON file: %w", err)
	}
	if err := tempFile.Sync(); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("sync temporary JSON file: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("close temporary JSON file: %w", err)
	}
	if err := renameSavedFile(tempPath, targetFile); err != nil {
		return fmt.Errorf("replace target JSON file: %w", err)
	}
	committed = true
	return nil
}

func savedFileMode(targetFile string) (os.FileMode, error) {
	info, err := os.Lstat(targetFile)
	if errors.Is(err, os.ErrNotExist) {
		return savedJSONFileMode, nil
	}
	if err != nil {
		return 0, fmt.Errorf("inspect target JSON file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return 0, fmt.Errorf("target JSON file %q is a symbolic link", targetFile)
	}
	if !info.Mode().IsRegular() {
		return 0, fmt.Errorf("target JSON file %q is not a regular file", targetFile)
	}
	return info.Mode().Perm(), nil
}

// HttpDelete provides a low-level capability to send a HTTP DELETE request and serialize the response as a string.
//
// Deprecated: use methods of the KSCloudAPI client instead.
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

// HttpGetter provides a low-level capability to send a HTTP GET request and serialize the response as a string.
//
// Deprecated: use methods of the KSCloudAPI client instead.
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

func setHeaders(req *http.Request, headers map[string]string) {
	// range over a nil map is a no-op, so headers being nil needs no guard here.
	for k, v := range headers {
		req.Header.Set(k, v)
	}
}

// httpRespToString parses the body as string and checks the HTTP status code, it closes the body reader at the end
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
		respStrNewLen := min(len(respStr), 1024)
		return "", fmt.Errorf("http-error: '%s', reason: '%s'", resp.Status, respStr[:respStrNewLen])
		// return "", fmt.Errorf("HTTP request failed. URL: '%s', Read-ERROR: '%s', HTTP-CODE: '%s', BODY(top): '%s', HTTP-HEADERS: %v, HTTP-BODY-BUFFER-LENGTH: %v", resp.Request.URL.RequestURI(), err, resp.Status, respStr[:respStrNewLen], resp.Header, bytesNum)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respStrNewLen := min(len(respStr), 1024)
		err = fmt.Errorf("http-error: '%s', reason: '%s'", resp.Status, respStr[:respStrNewLen])
	}

	return respStr, err
}
