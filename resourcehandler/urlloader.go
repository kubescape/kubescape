package resourcehandler

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/armosec/k8s-interface/k8sinterface"
	"github.com/armosec/kubescape/cautils"
)

func loadResourcesFromUrl(inputPatterns []string) ([]k8sinterface.IWorkload, error) {
	urls := listUrls(inputPatterns)
	if len(urls) == 0 {
		return nil, nil
	}

	workloads, errs := downloadFiles(urls)
	if len(errs) > 0 {
		cautils.ErrorDisplay(fmt.Sprintf("%v", errs)) // TODO - print error
	}
	return workloads, nil
}

func listUrls(patterns []string) []string {
	urls := []string{}
	for i := range patterns {
		if strings.HasPrefix(patterns[i], "http") {
			if !isYaml(patterns[i]) || !isJson(patterns[i]) { // if url of repo
				if yamls, err := ScanRepository(patterns[i], ""); err == nil { // TODO - support branch
					urls = append(urls, yamls...)
				} else {
					fmt.Print(err) // TODO - handle errors
				}
			} else { // url of single file
				urls = append(urls, patterns[i])
			}
		}
	}

	return urls
}

func downloadFiles(urls []string) ([]k8sinterface.IWorkload, []error) {
	workloads := []k8sinterface.IWorkload{}
	errs := []error{}
	for i := range urls {
		f, err := downloadFile(urls[i])
		if err != nil {
			errs = append(errs, err)
			continue
		}
		w, e := readFile(f, getFileFormat(urls[i]))
		errs = append(errs, e...)
		if w != nil {
			workloads = append(workloads, w...)
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
