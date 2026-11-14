package opaprocessor

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/kubescape/opa-utils/resources"
	"github.com/stretchr/testify/require"
)

func TestFinalizationIsIdempotent(t *testing.T) {
	session, _ := brokenRuleSession()
	p := NewOPAProcessor(session, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
	require.NoError(t, p.ProcessRulesListener(context.Background(), nil))
	before, err := json.Marshal(struct{ Report, Coverage, Namespaces any }{session.Report, session.ScanCoverage, session.NamespaceSummaries})
	require.NoError(t, err)
	p.finalizeResults(context.Background())
	after, err := json.Marshal(struct{ Report, Coverage, Namespaces any }{session.Report, session.ScanCoverage, session.NamespaceSummaries})
	require.NoError(t, err)
	require.JSONEq(t, string(before), string(after))
}
