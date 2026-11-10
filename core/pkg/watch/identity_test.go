package watch

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixtureResource is one resource of a synthetic report. ID is the positional
// resource ID the scanner would have assigned.
type fixtureResource struct {
	ID        string
	File      string
	APIVer    string
	Kind      string
	Namespace string
	Name      string
	// Failing lists control IDs the resource fails. Each failure carries one
	// evidence path that refers back to the resource by ID, as a real report does.
	Failing []string
	// Related lists extra resource IDs referenced from the evidence.
	Related []string
}

type fixtureOptions struct {
	coverage  map[string]any
	noObject  bool
	subStatus string
}

func buildReport(t *testing.T, resources []fixtureResource, opts ...func(*fixtureOptions)) []byte {
	t.Helper()
	var o fixtureOptions
	for _, opt := range opts {
		opt(&o)
	}
	controls := map[string]any{"C-0001": map[string]any{"scoreFactor": 7.0}, "C-0002": map[string]any{"scoreFactor": 3.0}}
	// Empty, not nil: a nil slice would marshal as "results": null, which is not a valid scan.
	results, resourceList := []any{}, []any{}
	for _, r := range resources {
		var associated []any
		for _, id := range []string{"C-0001", "C-0002"} {
			status := "passed"
			var rules []any
			for _, failing := range r.Failing {
				if failing == id {
					status = "failed"
					path := map[string]any{"resourceID": r.ID, "failedPath": "spec.containers[0].image"}
					rule := map[string]any{"name": "rule-" + id, "status": "failed", "paths": []any{path}}
					if len(r.Related) > 0 {
						related := make([]any, len(r.Related))
						for i, rel := range r.Related {
							related[i] = rel
						}
						rule["relatedResourcesIDs"] = related
						for _, rel := range r.Related {
							rule["paths"] = append(rule["paths"].([]any), map[string]any{"resourceID": rel, "failedPath": "rules"})
						}
					}
					rules = append(rules, rule)
				}
			}
			associated = append(associated, map[string]any{
				"controlID": id, "name": "control " + id,
				"status": statusOf(status, o.subStatus), "rules": rules,
			})
		}
		results = append(results, map[string]any{"resourceID": r.ID, "controls": associated})

		entry := map[string]any{"resourceID": r.ID}
		if !o.noObject {
			metadata := map[string]any{"name": r.Name}
			if r.Namespace != "" {
				metadata["namespace"] = r.Namespace
			}
			entry["object"] = map[string]any{"apiVersion": r.APIVer, "kind": r.Kind, "metadata": metadata}
			entry["source"] = map[string]any{"relativePath": r.File}
		}
		resourceList = append(resourceList, entry)
	}
	report := map[string]any{
		"results":        results,
		"resources":      resourceList,
		"summaryDetails": map[string]any{"controls": controls},
	}
	if o.coverage != nil {
		report["scanCoverage"] = o.coverage
	}
	data, err := json.Marshal(report)
	require.NoError(t, err)
	return data
}

func statusOf(status, subStatus string) map[string]any {
	out := map[string]any{"status": status}
	if subStatus != "" {
		out["subStatus"] = subStatus
	}
	return out
}

func withSubStatus(subStatus string) func(*fixtureOptions) {
	return func(o *fixtureOptions) { o.subStatus = subStatus }
}

func withCoverage(coverage map[string]any) func(*fixtureOptions) {
	return func(o *fixtureOptions) { o.coverage = coverage }
}

func withoutObjects(o *fixtureOptions) { o.noObject = true }

func deployment(id, file, name string, failing ...string) fixtureResource {
	return fixtureResource{ID: id, File: file, APIVer: "apps/v1", Kind: "Deployment", Namespace: "default", Name: name, Failing: failing}
}

func TestIdentity(t *testing.T) {
	object := func(apiVersion, kind, namespace, name string) map[string]any {
		metadata := map[string]any{"name": name}
		if namespace != "" {
			metadata["namespace"] = namespace
		}
		return map[string]any{"apiVersion": apiVersion, "kind": kind, "metadata": metadata}
	}

	assert.Equal(t, "dir/a.yaml::apps/v1::default::Deployment::web",
		Identity("dir/a.yaml", object("apps/v1", "Deployment", "default", "web")))
	assert.Equal(t, "a.yaml::v1::_::ConfigMap::cm",
		Identity("a.yaml", object("v1", "ConfigMap", "", "cm")), "a missing namespace is normalized")
	assert.Equal(t, "dir/a.yaml::v1::_::Namespace::ns",
		Identity(filepath.Join("dir", "a.yaml"), object("v1", "Namespace", "", "ns")), "path separators are normalized")
	assert.NotEqual(t,
		Identity("a.yaml", object("apps/v1", "Deployment", "default", "web")),
		Identity("a.yaml", object("apps/v1", "Deployment", "prod", "web")), "namespace is part of the identity")
	assert.NotEqual(t,
		Identity("a.yaml", object("apps/v1", "Deployment", "default", "web")),
		Identity("a.yaml", object("apps/v1", "StatefulSet", "default", "web")), "kind is part of the identity")
	assert.NotEqual(t,
		Identity("a.yaml", object("apps/v1", "Deployment", "default", "web")),
		Identity("b.yaml", object("apps/v1", "Deployment", "default", "web")), "file is part of the identity")

	assert.Empty(t, Identity("", object("v1", "Pod", "default", "p")), "no file means no identity")
	assert.Empty(t, Identity("a.yaml", nil))
	assert.Empty(t, Identity("a.yaml", object("v1", "", "default", "p")))
	assert.Empty(t, Identity("a.yaml", object("v1", "Pod", "default", "")))
}

func TestCanonicalizeRewritesEveryResourceID(t *testing.T) {
	data := buildReport(t, []fixtureResource{
		{ID: "path=1/web", File: "a.yaml", APIVer: "apps/v1", Kind: "Deployment", Namespace: "default", Name: "web", Failing: []string{"C-0001"}, Related: []string{"path=2/role"}},
		{ID: "path=2/role", File: "a.yaml", APIVer: "rbac.authorization.k8s.io/v1", Kind: "Role", Namespace: "default", Name: "role"},
	})

	canonical, err := Canonicalize(data)
	require.NoError(t, err)
	assert.Empty(t, canonical.Ambiguous)
	assert.NotContains(t, string(canonical.JSON), "path=", "no positional ID may survive anywhere in the report")

	web := "a.yaml::apps/v1::default::Deployment::web"
	role := "a.yaml::rbac.authorization.k8s.io/v1::default::Role::role"
	assert.Equal(t, map[string]struct{}{web: {}, role: {}}, canonical.Resources)

	var doc struct {
		Results []struct {
			ResourceID string `json:"resourceID"`
			Controls   []struct {
				Rules []struct {
					Paths   []struct{ ResourceID string } `json:"paths"`
					Related []string                      `json:"relatedResourcesIDs"`
				} `json:"rules"`
			} `json:"controls"`
		} `json:"results"`
	}
	require.NoError(t, json.Unmarshal(canonical.JSON, &doc))
	assert.Equal(t, web, doc.Results[0].ResourceID)
	rule := doc.Results[0].Controls[0].Rules[0]
	assert.Equal(t, web, rule.Paths[0].ResourceID)
	assert.Equal(t, role, rule.Paths[1].ResourceID)
	assert.Equal(t, []string{role}, rule.Related)
}

func TestCanonicalizeKeepsUnrelatedFieldsAndNumbers(t *testing.T) {
	data := []byte(`{"results":[],"summaryDetails":{"controls":{}},"extra":{"score":12345678901234567890,"nested":[1.50,"x"]}}`)
	canonical, err := Canonicalize(data)
	require.NoError(t, err)
	assert.Contains(t, string(canonical.JSON), `12345678901234567890`)
	assert.Contains(t, string(canonical.JSON), `1.50`)
	assert.Contains(t, string(canonical.JSON), `"nested"`)
}

func TestCanonicalizeEmptyReport(t *testing.T) {
	canonical, err := Canonicalize([]byte(`{"results":[],"summaryDetails":{"controls":{}}}`))
	require.NoError(t, err)
	assert.Empty(t, canonical.Resources)
	assert.Empty(t, canonical.Ambiguous)
}

func TestCanonicalizeRefusesAReportWithoutResources(t *testing.T) {
	data := buildReport(t, []fixtureResource{deployment("path=1/web", "a.yaml", "web", "C-0001")}, withoutObjects)
	// --omit-raw-resources drops resources[] entirely.
	var doc map[string]any
	require.NoError(t, json.Unmarshal(data, &doc))
	delete(doc, "resources")
	data, err := json.Marshal(doc)
	require.NoError(t, err)

	_, err = Canonicalize(data)
	require.ErrorIs(t, err, ErrNoResourceIdentity)
}

func TestCanonicalizeRejectsInvalidJSON(t *testing.T) {
	for _, input := range []string{``, `[]`, `null`, `{`, `not json`} {
		_, err := Canonicalize([]byte(input))
		assert.Error(t, err, "input %q", input)
	}
}

func TestCanonicalizeExcludesDuplicateIdentities(t *testing.T) {
	data := buildReport(t, []fixtureResource{
		deployment("path=1/web", "a.yaml", "web", "C-0001"),
		deployment("path=2/web", "a.yaml", "web"),
		deployment("path=3/api", "a.yaml", "api", "C-0002"),
	})

	canonical, err := Canonicalize(data)
	require.NoError(t, err)

	dup := "a.yaml::apps/v1::default::Deployment::web"
	require.Contains(t, canonical.Ambiguous, dup)
	assert.Contains(t, canonical.Ambiguous[dup], "2 resources")
	assert.NotContains(t, canonical.Resources, dup)
	assert.Contains(t, canonical.Resources, "a.yaml::apps/v1::default::Deployment::api")
	assert.NotContains(t, string(canonical.JSON), `"web"`, "neither duplicate may stay among the resources")

	// Their results are kept, each under an ID no other report can share.
	require.Len(t, canonical.Withheld, 2)
	for id, reason := range canonical.Withheld {
		assert.Contains(t, id, dup)
		assert.Contains(t, reason, "2 resources")
		assert.Contains(t, string(canonical.JSON), id)
	}
}

func TestCanonicalizeKeepsEveryResultOfDuplicateIdentities(t *testing.T) {
	data := buildReport(t, []fixtureResource{
		deployment("path=1/web", "a.yaml", "web", "C-0001", "C-0002"),
		deployment("path=2/web", "a.yaml", "web", "C-0001"),
	})

	canonical, err := Canonicalize(data)
	require.NoError(t, err)

	var doc struct {
		Results []struct {
			ResourceID string `json:"resourceID"`
			Controls   []struct {
				ControlID string `json:"controlID"`
				Status    struct {
					Status string `json:"status"`
				} `json:"status"`
			} `json:"controls"`
		} `json:"results"`
	}
	require.NoError(t, json.Unmarshal(canonical.JSON, &doc))
	require.Len(t, doc.Results, 2, "no result is dropped or merged")
	assert.NotEqual(t, doc.Results[0].ResourceID, doc.Results[1].ResourceID)
	failed := 0
	for _, result := range doc.Results {
		for _, control := range result.Controls {
			if control.Status.Status == "failed" {
				failed++
			}
		}
	}
	assert.Equal(t, 3, failed, "every failing control of both duplicates survives")
}

func TestCanonicalizeCountsResourcesWithoutResultsAsPresent(t *testing.T) {
	data := withoutResult(t, buildReport(t, []fixtureResource{
		deployment("path=1/web", "a.yaml", "web"),
		deployment("path=2/api", "a.yaml", "api", "C-0002"),
	}), "path=1/web")

	canonical, err := Canonicalize(data)
	require.NoError(t, err)

	assert.Contains(t, canonical.Resources, "a.yaml::apps/v1::default::Deployment::web", "a resource with no results is still in the scan")
	assert.Contains(t, canonical.Resources, "a.yaml::apps/v1::default::Deployment::api")
	assert.Empty(t, canonical.Ambiguous)
}

func TestCanonicalizeExcludesUnidentifiableResources(t *testing.T) {
	data := buildReport(t, []fixtureResource{
		deployment("path=1/web", "", "web", "C-0001"), // no source file
		deployment("path=2/api", "a.yaml", "api"),
	})

	canonical, err := Canonicalize(data)
	require.NoError(t, err)
	require.Contains(t, canonical.Ambiguous, "path=1/web")
	assert.Contains(t, canonical.Resources, "a.yaml::apps/v1::default::Deployment::api")
	assert.Len(t, canonical.Resources, 1)

	// The result is kept under an ID of its own, and its control is recorded.
	require.Len(t, canonical.Withheld, 1)
	assert.Contains(t, canonical.Withheld, "unidentified#path=1/web")
	assert.Contains(t, canonical.UnidentifiedControls, "C-0001")
	assert.Contains(t, string(canonical.JSON), "unidentified#path=1/web")
}

func TestCanonicalizeExcludesResourceWithUnidentifiedEvidence(t *testing.T) {
	data := buildReport(t, []fixtureResource{
		{ID: "path=1/web", File: "a.yaml", APIVer: "apps/v1", Kind: "Deployment", Namespace: "default", Name: "web", Failing: []string{"C-0001"}, Related: []string{"path=9/ghost"}},
		deployment("path=2/api", "a.yaml", "api", "C-0002"),
	})

	canonical, err := Canonicalize(data)
	require.NoError(t, err)
	web := "a.yaml::apps/v1::default::Deployment::web"
	require.Contains(t, canonical.Ambiguous, web)
	assert.Contains(t, canonical.Ambiguous[web], "path=9/ghost")
	assert.NotContains(t, canonical.Resources, web)
	assert.Contains(t, canonical.Resources, "a.yaml::apps/v1::default::Deployment::api")
}

func TestCanonicalizeExcludesResourceWhoseEvidenceTargetIsAmbiguous(t *testing.T) {
	data := buildReport(t, []fixtureResource{
		{ID: "path=1/web", File: "a.yaml", APIVer: "apps/v1", Kind: "Deployment", Namespace: "default", Name: "web", Failing: []string{"C-0001"}, Related: []string{"path=2/role"}},
		{ID: "path=2/role", File: "a.yaml", APIVer: "rbac.authorization.k8s.io/v1", Kind: "Role", Namespace: "default", Name: "role"},
		{ID: "path=3/role", File: "a.yaml", APIVer: "rbac.authorization.k8s.io/v1", Kind: "Role", Namespace: "default", Name: "role"},
	})

	canonical, err := Canonicalize(data)
	require.NoError(t, err)
	assert.Empty(t, canonical.Resources, "the Deployment's evidence depends on an ambiguous Role")
	assert.Len(t, canonical.Ambiguous, 2)
}

func TestCanonicalizeDoesNotModifyItsInput(t *testing.T) {
	data := buildReport(t, []fixtureResource{deployment("path=1/web", "a.yaml", "web", "C-0001")})
	original := append([]byte(nil), data...)
	_, err := Canonicalize(data)
	require.NoError(t, err)
	assert.Equal(t, original, data)
}
