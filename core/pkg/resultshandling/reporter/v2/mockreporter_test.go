package reporter

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/reporter"
	"github.com/kubescape/kubescape/v2/internal/testutils"
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

			t.Run("mock reports should support GetURL", func(t *testing.T) {
				got := reportMock.GetURL()
				require.Equalf(t, tc.want, got,
					"ReportMock.GetURL() = %v, want %v", got, tc.want,
				)
			})

			t.Run("mock reports should support DisplayReportURL", func(t *testing.T) {
				capture, clean := captureStderr(t)
				defer clean()

				reportMock.DisplayReportURL()
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

const pathTestReport = "/k8s/v2/postureReport"

type (
	// mockableOPASessionObj reproduces OPASessionObj with concrete types instead of interfaces.
	// It may be unmarshaled from a JSON fixture.
	mockableOPASessionObj struct {
		K8SResources          *cautils.K8SResources
		ArmoResource          *cautils.KSResources
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
		*mockAPIOptions
	}

	mockAPIOption  func(*mockAPIOptions)
	mockAPIOptions struct {
		withError error // responds error systematically
		withAuth  bool  // asserts a token in headers
	}
	mockOPASessionOption  func(*mockOPASessionOptions)
	mockOPASessionOptions struct {
		growthFactor int
	}
)

// mockOPASessionObj builds an OPASessionObj from a JSON fixture.
func mockOPASessionObj(t testing.TB, opts ...mockOPASessionOption) *cautils.OPASessionObj {
	options := opaSessionOptions(opts)

	buf, err := os.ReadFile(filepath.Join(testutils.CurrentDir(), "testdata", "mock_opasessionobj.json"))
	require.NoError(t, err)

	var v mockableOPASessionObj
	require.NoError(t,
		json.Unmarshal(buf, &v),
	)

	if options.growthFactor > 0 {
		pickResource := func() string {
			return fmt.Sprintf("extra-resource-%d", rand.Intn(10000)) //nolint:gosec
		}

		var (
			resource    *workloadinterface.Workload
			result      resourcesresults.Result
			prioritized prioritization.PrioritizedResource
			source      reporthandling.Source
		)

		maxSize := 0 // pick the mocked item that has the largest serialization
		for _, val := range v.AllResources {
			b, err := json.Marshal(val)
			require.NoError(t, err)
			if len(b) > maxSize {
				resource = val
				maxSize = len(b)
			}
		}

		maxSize = 0
		for _, val := range v.ResourcesResult {
			b, err := json.Marshal(val)
			require.NoError(t, err)
			if len(b) > maxSize {
				result = val
				maxSize = len(b)
			}
		}

		maxSize = 0
		for _, val := range v.ResourcesPrioritized {
			b, err := json.Marshal(val)
			require.NoError(t, err)
			if len(b) > maxSize {
				prioritized = val
				maxSize = len(b)
			}
		}

		maxSize = 0
		for _, val := range v.ResourceSource {
			b, err := json.Marshal(val)
			require.NoError(t, err)
			if len(b) > maxSize {
				source = val
				maxSize = len(b)
			}
		}

		// duplicates mocked content over new random keys
		for i := 0; i < options.growthFactor; i++ {
			resourceID := pickResource()
			v.AllResources[resourceID] = resource

			thisResult := result
			if thisResult.RawResource != nil {
				cloneRaw := *thisResult.RawResource
				cloneRaw.ResourceID = resourceID
				thisResult.RawResource = &cloneRaw
			}

			if thisResult.PrioritizedResource != nil {
				clonePrioritized := *thisResult.PrioritizedResource
				clonePrioritized.ResourceID = resourceID
				thisResult.PrioritizedResource = &clonePrioritized
			}
			thisResult.ResourceID = resourceID

			v.ResourcesResult[resourceID] = thisResult

			thisPrioritized := prioritized
			thisPrioritized.ResourceID = resourceID
			v.ResourcesPrioritized[resourceID] = thisPrioritized

			v.ResourceSource[resourceID] = source
		}
	}

	o := cautils.OPASessionObj{
		K8SResources: v.K8SResources,
		ArmoResource: v.ArmoResource,
		AllPolicies:  v.AllPolicies,
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
func mockAPIServer(t testing.TB, opts ...mockAPIOption) *testServer {
	h := http.NewServeMux()

	server := &testServer{
		Server:         httptest.NewUnstartedServer(h),
		mockAPIOptions: apiOptions(opts),
	}

	h.HandleFunc(pathTestReport, func(w http.ResponseWriter, r *http.Request) {
		if os.Getenv("DEBUG_TEST") != "" {
			dump, _ := httputil.DumpRequest(r, true)
			t.Logf("%s\n", dump)
		}

		if server.withError != nil {
			http.Error(w, server.withError.Error(), http.StatusInternalServerError)

			return
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

		if contentType := r.Header.Get("Content-Type"); contentType != "application/json" {
			t.Error("invalid Content-Type header")
			w.WriteHeader(http.StatusBadRequest)

			return
		}

		// NOTE(fredbi): shouldn't we require an extra authentication on the server side (e.g. tenant's token)?
		if !server.AssertAuth(t, r) {
			w.WriteHeader(http.StatusUnauthorized)

			return
		}

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

func apiOptions(opts []mockAPIOption) *mockAPIOptions {
	o := &mockAPIOptions{}
	for _, apply := range opts {
		apply(o)
	}

	return o
}

func opaSessionOptions(opts []mockOPASessionOption) *mockOPASessionOptions {
	o := &mockOPASessionOptions{}
	for _, apply := range opts {
		apply(o)
	}

	return o
}

// AssertAuth asserts the presence of an Authorization Bearer token.
func (o *mockAPIOptions) AssertAuth(t testing.TB, r *http.Request) bool {
	if !o.withAuth {
		return true
	}

	header := r.Header.Get("Authorization")
	if !assert.NotEmpty(t, header) {
		return false
	}

	var token string
	_, err := fmt.Sscanf(header, "Bearer %s", &token)
	if !assert.NoError(t, err) {
		return false
	}

	return assert.NotEmpty(t, token)
}

func withAPIError(err error) mockAPIOption {
	return func(o *mockAPIOptions) {
		o.withError = err
	}
}

func withAPIAuth(enabled bool) mockAPIOption {
	return func(o *mockAPIOptions) {
		o.withAuth = enabled
	}
}

// withGrowMock self-replicate the inner structures of an OPA session to grow the output report.
func withGrowMock(growth int) mockOPASessionOption {
	return func(o *mockOPASessionOptions) {
		o.growthFactor = growth
	}
}
