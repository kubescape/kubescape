package reporter

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/armosec/kubescape/cautils"
	"github.com/gofrs/uuid"
)

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
	if err != nil {
		return strBuilder.String(), err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		err = fmt.Errorf("response status: %d. Content: %s", resp.StatusCode, strBuilder.String())
	}

	return strBuilder.String(), err
}

func initEventReceiverURL() *url.URL {
	urlObj := url.URL{}

	urlObj.Scheme = "https"
	urlObj.Host = "report.euprod1.cyberarmorsoft.com"
	urlObj.Path = "/k8s/postureReport"

	q := urlObj.Query()
	q.Add("customerGUID", uuid.FromStringOrNil(cautils.CustomerGUID).String())
	q.Add("clusterName", cautils.ClusterName)
	urlObj.RawQuery = q.Encode()

	return &urlObj
}

func hostToString(host *url.URL, reportID string) string {
	q := host.Query()
	if reportID != "" {
		q.Add("reportID", reportID) // TODO - do we add the reportID?
	}
	host.RawQuery = q.Encode()
	return host.String()
}
