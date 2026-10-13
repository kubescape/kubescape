package v1

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestControlExclusionsHTTPContract(t *testing.T) {
	for _, body := range []string{`{}`, `{"excludeControls":[]}`, `{"excludeControls":null}`} {
		t.Run("legacy "+body, func(t *testing.T) {
			request := httptest.NewRequest("POST", "/v1/scan", strings.NewReader(body))
			params, err := getScanParamsFromRequest(request, "legacy")
			require.NoError(t, err)
			require.Empty(t, params.scanInfo.ExcludeControls)
			require.True(t, params.scanInfo.FrameworkScan)
			require.True(t, params.scanInfo.ScanAll)
		})
	}

	request := httptest.NewRequest("POST", "/v1/scan", strings.NewReader(`{"excludeControls":["C-0069","C-0070"],"targetType":"framework","targetNames":["nsa"],"hostScanner":false}`))
	params, err := getScanParamsFromRequest(request, "excluded")
	require.NoError(t, err)
	require.Equal(t, []string{"C-0069", "C-0070"}, params.scanInfo.ExcludeControls, "a valid API request must reach the existing scanner filter")
	require.Len(t, params.policyIdentifiers, 1)
	require.Equal(t, "nsa", params.policyIdentifiers[0].Identifier)
	require.False(t, params.scanInfo.HostSensorEnabled.GetBool())

	ordinary := httptest.NewRequest("POST", "/v1/scan", strings.NewReader(`{}`))
	next, err := getScanParamsFromRequest(ordinary, "next")
	require.NoError(t, err)
	require.Empty(t, next.scanInfo.ExcludeControls, "one user's exclusions must not leak into a subsequent scan")
}

func TestControlExclusionsHTTPRejectsMalformedLists(t *testing.T) {
	for _, value := range []string{`"C-0069"`, `42`, `{}`, `[42]`, `[null]`, `[""]`, `[" "]`, `["C-0069",true]`} {
		t.Run(value, func(t *testing.T) {
			request := httptest.NewRequest("POST", "/v1/scan", strings.NewReader(`{"excludeControls":`+value+`}`))
			params, err := getScanParamsFromRequest(request, "invalid")
			require.Error(t, err, "invalid exclusions must fail before the request can be queued")
			require.Nil(t, params)
		})
	}
}
