package reporter

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	v1 "github.com/kubescape/backend/pkg/client/v1"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/require"
)

func TestSubmitSplitsBeforeFirstResultExceedsReportLimit(t *testing.T) {
	var (
		mu        sync.Mutex
		bodySizes []int
	)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		mu.Lock()
		bodySizes = append(bodySizes, len(body))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	})
	server := &testServer{Server: httptest.NewUnstartedServer(handler)}
	server.StartTLS()
	t.Cleanup(server.Close)

	const (
		accountID = "00000000-0000-0000-0000-000000000001"
		accessKey = "00000000-0000-0000-0000-000000000002"
	)
	cloudAPI, err := v1.NewKSCloudAPI(
		server.Root(),
		server.Root(),
		accountID,
		accessKey,
		v1.WithHTTPClient(hijackedClient(t, server)),
	)
	require.NoError(t, err)

	resources := make(map[string]workloadinterface.IMetadata, 2)
	for _, name := range []string{"first", "second"} {
		resource := workloadinterface.NewWorkloadObj(map[string]any{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata": map[string]any{
				"name":      name,
				"namespace": "default",
			},
			// Each individual ConfigMap stays below Kubernetes' 1 MiB limit.
			"data": map[string]any{"payload": strings.Repeat("x", 850*1024)},
		})
		resources[resource.GetID()] = resource
	}

	var resultResourceID string
	for resourceID := range resources {
		resultResourceID = resourceID
		break
	}
	session := &cautils.OPASessionObj{
		AllResources: resources,
		ResourcesResult: map[string]resourcesresults.Result{
			resultResourceID: {ResourceID: resultResourceID},
		},
		ResourceSource: map[string]reporthandling.Source{},
		Report:         &reporthandlingv2.PostureReport{},
		Metadata: &reporthandlingv2.Metadata{
			ScanMetadata: reporthandlingv2.ScanMetadata{ScanningTarget: reporthandlingv2.File},
		},
	}

	reporter := NewReportEventReceiver(
		&TenantConfigMock{accountID: accountID, accessKey: accessKey},
		"cbabd56f-bac6-416a-836b-b815ef347647",
		SubmitContextScan,
		cloudAPI,
	)
	require.NoError(t, reporter.Submit(context.Background(), session))

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, bodySizes, 2, "resources must be flushed before the first result is appended")
	for _, size := range bodySizes {
		require.Less(t, size, MAX_REPORT_SIZE, "submitted request exceeded the report-size limit")
	}
}
