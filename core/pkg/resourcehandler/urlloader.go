package resourcehandler

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/armosec/k8s-interface/workloadinterface"
	"github.com/armosec/kubescape/core/cautils"
	"github.com/armosec/kubescape/core/cautils/logger"
)

func loadResourcesFromUrl(inputPatterns []string) (map[string][]workloadinterface.IMetadata, error) {
	urls := listUrls(inputPatterns)
	if len(urls) == 0 {
		return nil, nil
	}

	workloads, errs := downloadFiles(urls)
	if len(errs) > 0 {
		logger.L().Error(fmt.Sprintf("%v", errs))
	}
	return workloads, nil
}

func listUrls(patterns []string) []string {
	urls := []string{}
	for i := range patterns {
		if strings.HasPrefix(patterns[i], "http") {
			if yamls, err := ScanRepository(patterns[i], ""); err == nil { // TODO - support branch
				urls = append(urls, yamls...)
			} else {
				logger.L().Error(err.Error())
			}
		}
	}

	return urls
}

func downloadFiles(urls []string) (map[string][]workloadinterface.IMetadata, []error) {
	workloads := make(map[string][]workloadinterface.IMetadata, 0)
	errs := []error{}
	for i := range urls {
		f, err := downloadFile(urls[i])
		if err != nil {
			errs = append(errs, err)
			continue
		}
		w, e := cautils.ReadFile(f, cautils.GetFileFormat(urls[i]))
		errs = append(errs, e...)
		if w != nil {
			if _, ok := workloads[urls[i]]; !ok {
				workloads[urls[i]] = make([]workloadinterface.IMetadata, 0)
			}
			wSlice := workloads[urls[i]]
			wSlice = append(wSlice, w...)
			workloads[urls[i]] = wSlice
		}
	}
	return workloads, errs
}

func downloadFile(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || 301 < resp.StatusCode {
		return nil, fmt.Errorf("failed to download file, url: '%s', status code: %s", url, resp.Status)
	}
	return streamToByte(resp.Body), nil
}

func streamToByte(stream io.Reader) []byte {
	buf := new(bytes.Buffer)
	buf.ReadFrom(stream)
	return buf.Bytes()
}
