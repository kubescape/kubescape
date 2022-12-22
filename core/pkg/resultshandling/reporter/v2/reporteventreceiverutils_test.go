package reporter

import (
	"net/url"
	"testing"
)

func TestHostToString(t *testing.T) {
	host := url.URL{
		Scheme:   "https",
		Host:     "report.eudev3.cyberarmorsoft.com",
		Path:     "k8srestapi/v2/postureReport",
		RawQuery: "cluster=openrasty_seal-7fvz&customerGUID=5d817063-096f-4d91-b39b-8665240080af",
	}
	expectedHost := "https://report.eudev3.cyberarmorsoft.com/k8srestapi/v2/postureReport?cluster=openrasty_seal-7fvz&customerGUID=5d817063-096f-4d91-b39b-8665240080af&reportGUID=ffdd2a00-4dc8-4bf3-b97a-a6d4fd198a41"
	receivedHost := hostToString(&host, "ffdd2a00-4dc8-4bf3-b97a-a6d4fd198a41")
	if receivedHost != expectedHost {
		t.Errorf("%s != %s", receivedHost, expectedHost)
	}
}
