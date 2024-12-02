package reporter

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/reporter"
	"github.com/kubescape/kubescape/v3/internal/testutils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/attacktrack/v1alpha1"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/prioritization"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReportMockGetURL(t *testing.T) {
	t.Parallel()

	type fields struct {
		query   string
		message string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "TestReportMock_GetURL",
			fields: fields{
				query:   "https://kubescape.io",
				message: "some message",
			},
			want: "https://kubescape.io",
		},
		{
			name: "TestReportMock_GetURL_empty",
			fields: fields{
				query:   "",
				message: "",
			},
			want: "",
		},
	}

	for _, toPin := range tests {
		tc := toPin

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var reportMock reporter.IReport = NewReportMock(tc.fields.query, tc.fields.message)

			t.Run("mock reports should support DisplayMessage", func(t *testing.T) {
				capture, clean := captureStderr(t)
				defer clean()

				reportMock.DisplayMessage()
				require.NoError(t, capture.Close())

				buf, err := os.ReadFile(capture.Name())
				require.NoError(t, err)

				if tc.fields.message != "" {
					require.NotEmpty(t, buf)
				} else {
					require.Empty(t, buf)
				}
			})

			t.Run("mock reports should support Submit", func(t *testing.T) {
				require.NoError(t,
					reportMock.Submit(context.Background(), &cautils.OPASessionObj{}),
				)
			})
		})
	}
}

func TestReportMock_strToDisplay(t *testing.T) {
	type fields struct {
		query   string
		message string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "TestReportMock_strToDisplay",
			fields: fields{
				query:   "https://kubescape.io",
				message: "some message",
			},
			want: "\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\nScan results have not been submitted: some message\nFor more details: https://kubescape.io\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n",
		},
		{
			name: "TestReportMock_strToDisplay_empty",
			fields: fields{
				query:   "https://kubescape.io",
				message: "",
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reportMock := &ReportMock{
				query:   tt.fields.query,
				message: tt.fields.message,
			}
			if got := reportMock.strToDisplay(); got != tt.want {
				t.Errorf("ReportMock.strToDisplay() = %v, want %v", got, tt.want)
			}
		})
	}
}

const pathTestReport = "/k8s/v2/postureReport"

type (
	// mockableOPASessionObj reproduces OPASessionObj with concrete types instead of interfaces.
	// It may be unmarshaled from a JSON fixture.
	mockableOPASessionObj struct {
		K8SResources          cautils.K8SResources
		ExternalResources     cautils.ExternalResources
		AllPolicies           *cautils.Policies
		AllResources          map[string]*workloadinterface.Workload
		ResourcesResult       map[string]resourcesresults.Result
		ResourceSource        map[string]reporthandling.Source
		ResourcesPrioritized  map[string]prioritization.PrioritizedResource
		ResourceAttackTracks  map[string]*v1alpha1.AttackTrack
		AttackTracks          map[string]*v1alpha1.AttackTrack
		Report                *reporthandlingv2.PostureReport
		RegoInputData         cautils.RegoInputData
		Metadata              *reporthandlingv2.Metadata
		InfoMap               map[string]apis.StatusInfo
		ResourceToControlsMap map[string][]string
		SessionID             string
		Policies              []reporthandling.Framework
		Exceptions            []armotypes.PostureExceptionPolicy
		OmitRawResources      bool
	}

	// testServer wraps a mock http server.
	//
	// It exposes a route to POST reports and asserts the submitted requests.
	testServer struct {
		*httptest.Server
	}

	// interceptor is a http.RoundTripper used to re-route the calls to the mock API server.
	//
	// NOTE(fredbi): ideally, the target URL is configurable so we don't need to resort to this to run tests.
	interceptor struct {
		original http.RoundTripper
		host     string
	}
)

// mockOPASessionObj builds an OPASessionObj from a JSON fixture.
func mockOPASessionObj(t testing.TB) *cautils.OPASessionObj {
	buf, err := os.ReadFile(filepath.Join(testutils.CurrentDir(), "testdata", "mock_opasessionobj.json"))
	require.NoError(t, err)

	var v mockableOPASessionObj
	require.NoError(t,
		json.Unmarshal(buf, &v),
	)

	o := cautils.OPASessionObj{
		K8SResources:      v.K8SResources,
		ExternalResources: v.ExternalResources,
		AllPolicies:       v.AllPolicies,
		//AllResources          map[string]*workloadinterface.Workload        // all scanned resources, map[<resource ID>]<resource>
		ResourcesResult:      v.ResourcesResult,
		ResourceSource:       v.ResourceSource,
		ResourcesPrioritized: v.ResourcesPrioritized,
		//ResourceAttackTracks  map[string]*v1alpha1.AttackTrack              // resources attack tracks, map[<resource ID>]<attack track>
		//AttackTracks          map[string]*v1alpha1.AttackTrack
		Report:                v.Report,
		RegoInputData:         v.RegoInputData,
		Metadata:              v.Metadata,
		InfoMap:               v.InfoMap,
		ResourceToControlsMap: v.ResourceToControlsMap,
		SessionID:             v.SessionID,
		Policies:              v.Policies,
		Exceptions:            v.Exceptions,
		OmitRawResources:      v.OmitRawResources,
	}

	o.AllResources = make(map[string]workloadinterface.IMetadata, len(v.AllResources))
	for k, val := range v.AllResources {
		o.AllResources[k] = val
	}

	o.ResourceAttackTracks = make(map[string]v1alpha1.IAttackTrack, len(v.ResourceAttackTracks))
	for k, val := range v.ResourceAttackTracks {
		o.ResourceAttackTracks[k] = val
	}

	o.AttackTracks = make(map[string]v1alpha1.IAttackTrack, len(v.AttackTracks))
	for k, val := range v.AttackTracks {
		o.AttackTracks[k] = val
	}

	return &o
}

func (s *testServer) Root() string {
	return s.Server.URL
}

func (s *testServer) URL(pth string) string {
	pth = strings.TrimLeft(pth, "/")

	return fmt.Sprintf("%s/%s", s.Server.URL, pth)
}

// mockAPIServer builds a mock API running with a TLS endpoint.
//
// Running tests with the DEBUG_TEST=1 environment will result in dumping a trace of
// the incoming requests.
func mockAPIServer(t testing.TB) *testServer {
	h := http.NewServeMux()

	server := &testServer{
		Server: httptest.NewUnstartedServer(h),
	}

	h.HandleFunc(pathTestReport, func(w http.ResponseWriter, r *http.Request) {
		if os.Getenv("DEBUG_TEST") != "" {
			dump, _ := httputil.DumpRequest(r, true)
			t.Logf("%s\n", dump)
		}

		if !assert.Equal(t, http.MethodPost, r.Method) {
			w.WriteHeader(http.StatusMethodNotAllowed)

			return
		}

		if !assert.NoErrorf(t, r.ParseForm(), "expected params to parse") {
			w.WriteHeader(http.StatusBadRequest)

			return
		}

		cluster := r.Form.Get("clusterName")
		contextName := r.Form.Get("contextName")
		customer := r.Form.Get("customerGUID")
		report := r.Form.Get("reportGUID")

		if cluster == "" || contextName == "" || customer == "" || report == "" {
			t.Error("missing query parameter")
			w.WriteHeader(http.StatusBadRequest)

			return
		}

		// NOTE(fredbi): (i)  requests should have header Content-Type: "application/json"
		// NOTE(fredbi): (ii) shouldn't we require an extra authentication (e.g. secretKey or Token)?

		buf, err := io.ReadAll(r.Body)
		defer func() {
			_ = r.Body.Close()
		}()

		if !assert.NoError(t, err) {
			w.WriteHeader(http.StatusInternalServerError)

			return
		}

		var input reporthandlingv2.PostureReport
		if !assert.NoError(t, json.Unmarshal(buf, &input)) {
			w.WriteHeader(http.StatusInternalServerError)

			return
		}
	})

	h.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		dump, _ := httputil.DumpRequest(r, true)
		t.Logf("%s\n", dump)

		t.Errorf("unexpected route in input request: %v", r.URL)

		w.WriteHeader(http.StatusNotFound)
	})

	server.StartTLS()

	return server
}

// newInterceptor builds a new http.RoundTripper to re-route outgoing requests.
func newInterceptor(transport http.RoundTripper, host string) *interceptor {
	return &interceptor{
		original: transport,
		host:     host,
	}
}

func (i *interceptor) RoundTrip(r *http.Request) (*http.Response, error) {
	defer r.Body.Close()

	hijacked := r.Clone(r.Context())
	hijacked.URL.Host = i.host

	return i.original.RoundTrip(hijacked)
}

// hijackedClient builds an HTTP client suited for working against a mock server.
//
// This client supports mocked TLS and re-routes outgoing calls to the local mock server.
func hijackedClient(t testing.TB, srv *testServer) *http.Client {
	tlsClient := srv.Client()
	transport, ok := tlsClient.Transport.(*http.Transport)
	require.True(t, ok)
	mockURL, err := url.Parse(srv.Root())
	require.NoError(t, err)

	return &http.Client{
		Transport: newInterceptor(transport, mockURL.Host),
	}
}
