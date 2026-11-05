package opaprocessor

import (
	"cmp"
	"context"
	"slices"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/scancache"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/kubescape/opa-utils/resources"
	"github.com/mitchellh/copystructure"
	"github.com/stretchr/testify/require"
)

// cacheScenario evaluates one control over a set of objects twice per step:
// once without the incremental cache and once through a cache persisted in a
// directory across steps, as consecutive scans would.
type cacheScenario struct {
	t       *testing.T
	control reporthandling.Control
	objects map[string]map[string]any // resource ID -> object
	keys    map[string]string         // resource ID -> K8SResources key
	dir     string

	// excludedNamespaces is passed to the processor as --exclude-namespaces.
	excludedNamespaces string
	// partitioned evaluates each namespace as its own scope, as the
	// streaming and large-cluster paths do.
	partitioned bool
}

func newCacheScenario(t *testing.T, control reporthandling.Control) *cacheScenario {
	t.Helper()
	return &cacheScenario{
		t:       t,
		control: control,
		objects: map[string]map[string]any{},
		keys:    map[string]string{},
		dir:     t.TempDir(),
	}
}

// put adds or replaces an object, indexed under key (e.g. "/v1/pods").
func (s *cacheScenario) put(key string, object map[string]any) string {
	id := objectsenvelopes.NewObject(object).GetID()
	s.objects[id] = object
	s.keys[id] = key
	return id
}

func (s *cacheScenario) session() *cautils.OPASessionObj {
	sess := cautils.NewOPASessionObjMock()
	sess.K8SResources = cautils.K8SResources{}
	for id, object := range s.objects {
		sess.AllResources[id] = objectsenvelopes.NewObject(cloneObject(s.t, object))
		sess.K8SResources[s.keys[id]] = append(sess.K8SResources[s.keys[id]], id)
	}
	for key := range sess.K8SResources {
		slices.Sort(sess.K8SResources[key])
	}
	sess.AllPolicies = cautils.NewPolicies()
	sess.AllPolicies.Controls[s.control.ControlID] = s.control
	return sess
}

func (s *cacheScenario) newProcessor(store *scancache.Store) *OPAProcessor {
	opap := NewOPAProcessor(s.session(), resources.NewRegoDependenciesDataMock(), "test", s.excludedNamespaces, "", false, nil)
	if s.partitioned {
		opap.largeClusterSizeThreshold = 1
	}
	if store != nil {
		opap.SetIncrementalCache(store)
	}
	return opap
}

func (s *cacheScenario) evaluate(store *scancache.Store) map[string]scenarioVerdict {
	s.t.Helper()
	opap := s.newProcessor(store)
	control := s.control
	got, err := opap.processControl(context.Background(), &control, evaluationScope{})
	require.NoError(s.t, err)
	return scenarioVerdicts(got)
}

// step evaluates the current objects without and with the persisted cache.
func (s *cacheScenario) step() (full, incremental map[string]scenarioVerdict) {
	s.t.Helper()
	full = s.evaluate(nil)
	store := s.loadStore()
	incremental = s.evaluate(store)
	require.NoError(s.t, store.Flush())
	return full, incremental
}

// cached reports whether the persisted cache holds a verdict of the control
// for the object with id, as it is now.
func (s *cacheScenario) cached(id string) bool {
	s.t.Helper()
	_, ok := s.loadStore().Get(s.control.ControlID, id, scancache.ResourceHash(s.objects[id]))
	return ok
}

func (s *cacheScenario) loadStore() *scancache.Store {
	s.t.Helper()
	store, err := scancache.Load(s.dir, "scenario")
	require.NoError(s.t, err)
	return store
}

// scenarioVerdict is the structured part of a control result the cache must
// reproduce: per-rule status and paths, compared without depending on the
// order results were produced in.
type scenarioVerdict struct {
	Status string
	Rules  []scenarioRuleVerdict
}

type scenarioRuleVerdict struct {
	Name      string
	Status    string
	SubStatus string
	Paths     []armotypes.PosturePaths
}

func scenarioVerdicts(results map[string]resourcesresults.ResourceAssociatedControl) map[string]scenarioVerdict {
	out := make(map[string]scenarioVerdict, len(results))
	for id, result := range results {
		verdict := scenarioVerdict{Status: string(result.GetStatus(nil).Status())}
		for _, rule := range result.ResourceAssociatedRules {
			paths := slices.Clone(rule.Paths)
			slices.SortFunc(paths, scenarioComparePaths)
			verdict.Rules = append(verdict.Rules, scenarioRuleVerdict{
				Name:      rule.Name,
				Status:    string(rule.Status),
				SubStatus: string(rule.SubStatus),
				Paths:     paths,
			})
		}
		slices.SortFunc(verdict.Rules, func(a, b scenarioRuleVerdict) int {
			return cmp.Compare(a.Name, b.Name)
		})
		out[id] = verdict
	}
	return out
}

// scenarioComparePaths orders paths for comparison. It deliberately does not
// reuse production code, so these scenarios also run against code that
// predates the attribution check.
func scenarioComparePaths(a, b armotypes.PosturePaths) int {
	return cmp.Or(
		cmp.Compare(a.ResourceID, b.ResourceID),
		cmp.Compare(a.FailedPath, b.FailedPath),
		cmp.Compare(a.ReviewPath, b.ReviewPath),
		cmp.Compare(a.DeletePath, b.DeletePath),
		cmp.Compare(a.FixPath.Path, b.FixPath.Path),
		cmp.Compare(a.FixPath.Value, b.FixPath.Value),
		cmp.Compare(a.FixCommand, b.FixCommand),
	)
}

func cloneObject(t *testing.T, object map[string]any) map[string]any {
	t.Helper()
	clone, err := copystructure.Copy(object)
	require.NoError(t, err)
	return clone.(map[string]any)
}

// regoControl builds a single-rule Rego control matching kinds in the core
// and apps groups.
func regoControl(controlID, ruleName, rego string, kinds ...string) reporthandling.Control {
	rule := reporthandling.PolicyRule{
		PortalBase:   armotypes.PortalBase{Name: ruleName, Attributes: map[string]any{}},
		Rule:         rego,
		RuleLanguage: reporthandling.RegoLanguage,
		Match: []reporthandling.RuleMatchObjects{
			{APIGroups: []string{"", "apps"}, APIVersions: []string{"v1"}, Resources: kinds},
		},
	}
	control := reporthandling.Control{ControlID: controlID, Rules: []reporthandling.PolicyRule{rule}}
	control.Name = controlID
	return control
}

func podObject(namespace, name string, spec map[string]any) map[string]any {
	return map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": name, "namespace": namespace},
		"spec":       spec,
	}
}
