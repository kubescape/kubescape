package printer

import (
	"context"
	"os"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type customTestCatalog struct {
	items    map[string]workloadinterface.IMetadata
	getCalls map[string]int
}

func newCustomTestCatalog() *customTestCatalog {
	return &customTestCatalog{
		items:    make(map[string]workloadinterface.IMetadata),
		getCalls: make(map[string]int),
	}
}

func (c *customTestCatalog) Get(id string) (workloadinterface.IMetadata, bool) {
	c.getCalls[id]++
	res, ok := c.items[id]
	return res, ok
}

func (c *customTestCatalog) Add(resource workloadinterface.IMetadata) {
	if resource != nil {
		c.items[resource.GetID()] = resource
	}
}

func (c *customTestCatalog) AddAll(resources map[string]workloadinterface.IMetadata) {
	for _, res := range resources {
		c.Add(res)
	}
}

func (c *customTestCatalog) Remove(id string) {
	delete(c.items, id)
}

func (c *customTestCatalog) Len() int {
	return len(c.items)
}

func (c *customTestCatalog) ListIDs() []string {
	ids := make([]string, 0, len(c.items))
	for k := range c.items {
		ids = append(ids, k)
	}
	return ids
}

func (c *customTestCatalog) ForEach(fn func(id string, resource workloadinterface.IMetadata) bool) {
	for k, v := range c.items {
		if !fn(k, v) {
			break
		}
	}
}

func (c *customTestCatalog) All() map[string]workloadinterface.IMetadata {
	return c.items
}

var _ cautils.ResourceCatalog = (*customTestCatalog)(nil)

func createTestWorkload(name, kind, namespace string) workloadinterface.IMetadata {
	return workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "apps/v1",
		"kind":       kind,
		"metadata": map[string]any{
			"name":      name,
			"namespace": namespace,
			"labels": map[string]any{
				"app": name,
			},
		},
	})
}

func setupTestSessionWithCatalog() (*cautils.OPASessionObj, *customTestCatalog) {
	wl1 := createTestWorkload("app-1", "Deployment", "prod")
	wl2 := createTestWorkload("app-2", "Pod", "staging")

	cat := newCustomTestCatalog()
	cat.Add(wl1)
	cat.Add(wl2)

	ctrlSummary := reportsummary.ControlSummary{
		ControlID:   "C-0001",
		ScoreFactor: 7,
		StatusInfo:  apis.StatusInfo{InnerStatus: apis.StatusFailed},
	}
	ctrlSummary.Append(&apis.StatusInfo{InnerStatus: apis.StatusFailed}, wl1.GetID())

	session := &cautils.OPASessionObj{
		Report: &reporthandlingv2.PostureReport{
			SummaryDetails: reportsummary.SummaryDetails{
				Controls: map[string]reportsummary.ControlSummary{
					"C-0001": ctrlSummary,
				},
			},
		},
		ResourcesResult: map[string]resourcesresults.Result{
			wl1.GetID(): {
				ResourceID: wl1.GetID(),
				AssociatedControls: []resourcesresults.ResourceAssociatedControl{
					{
						ControlID: "C-0001",
						Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
					},
				},
			},
		},
	}

	session.SetCatalog(cat)
	return session, cat
}

func TestPrinters_FunctionWithCatalogWhenAllResourcesNil(t *testing.T) {
	ctx := context.Background()

	t.Run("FinalizeResults", func(t *testing.T) {
		session, cat := setupTestSessionWithCatalog()
		assert.Nil(t, session.AllResources, "AllResources must be nil for custom catalog")

		report := FinalizeResults(session)
		require.NotNil(t, report)
		assert.Greater(t, cat.getCalls[session.ResourcesResult[report.Results[0].ResourceID].ResourceID], 0,
			"FinalizeResults should fetch resource via catalog.Get")
	})

	t.Run("ConvertToPostureReportWithSeverityLabelsAndCoverageFromCatalog", func(t *testing.T) {
		session, cat := setupTestSessionWithCatalog()
		finalized := FinalizeResults(session)

		enriched := ConvertToPostureReportWithSeverityLabelsAndCoverageFromCatalog(
			finalized,
			session.LabelsToCopy,
			cat,
			&session.ScanCoverage,
		)
		require.NotNil(t, enriched)
		assert.NotEmpty(t, enriched.SummaryDetails.Controls)
	})

	t.Run("listResultSummaryFromCatalog", func(t *testing.T) {
		session, cat := setupTestSessionWithCatalog()
		ctrl := session.Report.SummaryDetails.Controls["C-0001"]

		summaries := listResultSummaryFromCatalog(&ctrl, cat)
		require.Len(t, summaries, 1)
		assert.Equal(t, "app-1", summaries[0].resource.GetName())
	})

	t.Run("JsonPrinter", func(t *testing.T) {
		session, _ := setupTestSessionWithCatalog()
		tmp, err := os.CreateTemp("", "test-json-*.json")
		require.NoError(t, err)
		defer os.Remove(tmp.Name())

		p := NewJsonPrinter()
		p.writer = tmp
		err = p.ActionPrint(ctx, session, nil)
		require.NoError(t, err)
		_ = tmp.Close()

		data, err := os.ReadFile(tmp.Name())
		require.NoError(t, err)
		assert.NotEmpty(t, data)
	})

	t.Run("YamlPrinter", func(t *testing.T) {
		session, _ := setupTestSessionWithCatalog()
		tmp, err := os.CreateTemp("", "test-yaml-*.yaml")
		require.NoError(t, err)
		defer os.Remove(tmp.Name())

		p := NewYamlPrinter()
		p.writer = tmp
		err = p.ActionPrint(ctx, session, nil)
		require.NoError(t, err)
		_ = tmp.Close()

		data, err := os.ReadFile(tmp.Name())
		require.NoError(t, err)
		assert.NotEmpty(t, data)
	})

	t.Run("HandleNilResourceLookupGracefully", func(t *testing.T) {
		cat := newCustomTestCatalog()
		// Store explicit nil value for a resource ID (returns nil, true)
		cat.items["nil-res"] = nil

		ctrlSummary := reportsummary.ControlSummary{
			ControlID:   "C-0001",
			ScoreFactor: 7,
			StatusInfo:  apis.StatusInfo{InnerStatus: apis.StatusFailed},
		}
		ctrlSummary.Append(&apis.StatusInfo{InnerStatus: apis.StatusFailed}, "nil-res")

		session := &cautils.OPASessionObj{
			Report: &reporthandlingv2.PostureReport{
				SummaryDetails: reportsummary.SummaryDetails{
					Controls: map[string]reportsummary.ControlSummary{
						"C-0001": ctrlSummary,
					},
				},
			},
			ResourcesResult: map[string]resourcesresults.Result{
				"nil-res": {
					ResourceID: "nil-res",
					AssociatedControls: []resourcesresults.ResourceAssociatedControl{
						{
							ControlID: "C-0001",
							Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
						},
					},
				},
			},
		}
		session.SetCatalog(cat)

		// 1. htmlprinter buildResourceTableView should skip nil-res
		assert.NotPanics(t, func() {
			tv := buildResourceTableView(session, false)
			assert.Empty(t, tv)
		})

		// 2. resourcetable failedResourcesInPrintOrder should skip nil-res
		assert.NotPanics(t, func() {
			ordered := failedResourcesInPrintOrder(session)
			assert.Empty(t, ordered)
		})

		// 3. markdownprinter should emit placeholder row without panicking
		assert.NotPanics(t, func() {
			tmp, err := os.CreateTemp("", "test-md-*.md")
			require.NoError(t, err)
			defer os.Remove(tmp.Name())

			mp := NewMarkdownPrinter()
			mp.writer = tmp
			err = mp.ActionPrint(ctx, session, nil)
			require.NoError(t, err)
			_ = tmp.Close()

			data, err := os.ReadFile(tmp.Name())
			require.NoError(t, err)
			assert.Contains(t, string(data), "nil-res")
		})

		// 4. junitprinter should fallback to resource ID without panicking
		assert.NotPanics(t, func() {
			tmp, err := os.CreateTemp("", "test-junit-*.xml")
			require.NoError(t, err)
			defer os.Remove(tmp.Name())

			jp := NewJunitPrinter(false)
			jp.writer = tmp
			err = jp.ActionPrint(ctx, session, nil)
			require.NoError(t, err)
			_ = tmp.Close()

			data, err := os.ReadFile(tmp.Name())
			require.NoError(t, err)
			assert.Contains(t, string(data), "resourceID: nil-res")
		})
	})
}
