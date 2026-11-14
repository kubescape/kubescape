package watch

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/diff"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The scenarios are made from the reports a real scan wrote (testdata), changed
// the way a real change to the manifests changes them, so that the identities,
// source fields, evidence and coverage are those a scan produces.

const (
	frontendInA   = "a.yaml::apps/v1::default::Deployment::frontend"
	backendInB    = "b.yaml::apps/v1::default::Deployment::backend"
	frontendMoved = "renamed.yaml::apps/v1::default::Deployment::frontend"
)

type scanDoc map[string]any

func decodeScan(t *testing.T, raw []byte) scanDoc {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var doc scanDoc
	require.NoError(t, decoder.Decode(&doc))
	return doc
}

func loadScan(t *testing.T, name string) scanDoc { return decodeScan(t, fixture(t, name)) }

func (d scanDoc) encode(t *testing.T) []byte {
	t.Helper()
	raw, err := json.Marshal(d)
	require.NoError(t, err)
	return raw
}

// resourcesAt returns the resources a scan read from a file.
func (d scanDoc) resourcesAt(file string) []map[string]any {
	var found []map[string]any
	for _, raw := range d["resources"].([]any) {
		resource := raw.(map[string]any)
		source, _ := resource["source"].(map[string]any)
		if source["relativePath"] == file {
			found = append(found, resource)
		}
	}
	return found
}

var idPath = regexp.MustCompile(`^path=(\d+)/`)

// movedID is the ID a scan gives the same resource in another file: its leading
// hash is of the path, and so is another number.
func movedID(t *testing.T, id string, shift int) string {
	t.Helper()
	match := idPath.FindStringSubmatch(id)
	require.NotNil(t, match, id)
	n, err := strconv.Atoi(match[1])
	require.NoError(t, err)
	return idPath.ReplaceAllString(id, fmt.Sprintf("path=%d/", n+shift))
}

// replaceEverywhere rewrites a string wherever the report holds it: in the
// resource, its results and the evidence that names it.
func (d scanDoc) replaceEverywhere(t *testing.T, old, replacement string) scanDoc {
	t.Helper()
	return decodeScan(t, []byte(strings.ReplaceAll(string(d.encode(t)), old, replacement)))
}

// renamed is the scan after file from was renamed to file to: same content, new
// path, so new IDs, source and position fields.
func (d scanDoc) renamed(t *testing.T, from, to string) scanDoc {
	t.Helper()
	doc := d
	for _, resource := range d.resourcesAt(from) {
		oldID := resource["resourceID"].(string)
		doc = doc.replaceEverywhere(t, oldID, movedID(t, oldID, 1000003))
	}
	for _, resource := range doc.resourcesAt(from) {
		position := strings.SplitN(resource["object"].(map[string]any)["sourcePath"].(string), ":", 2)[1]
		resource["source"].(map[string]any)["relativePath"] = to
		resource["object"].(map[string]any)["sourcePath"] = to + ":" + position
	}
	return doc
}

// copied adds the resources of file from, as the same manifest in file to; name,
// when it is not empty, renames the Deployment in the copy.
func (d scanDoc) copied(t *testing.T, from, to, name string, shift int) scanDoc {
	t.Helper()
	doc := decodeScan(t, d.encode(t))
	for _, resource := range d.resourcesAt(from) {
		oldID := resource["resourceID"].(string)
		newID := movedID(t, oldID, shift)
		if name != "" {
			newID = newID[:strings.LastIndex(newID, "/")+1] + name
		}
		clone := decodeScan(t, mustJSON(t, resource))
		clone["resourceID"] = newID
		position := strings.SplitN(clone["object"].(map[string]any)["sourcePath"].(string), ":", 2)[1]
		clone["source"].(map[string]any)["relativePath"] = to
		clone["object"].(map[string]any)["sourcePath"] = to + ":" + position
		if name != "" {
			clone["object"].(map[string]any)["metadata"].(map[string]any)["name"] = name
		}
		doc["resources"] = append(doc["resources"].([]any), map[string]any(clone))

		for _, raw := range d["results"].([]any) {
			result := raw.(map[string]any)
			if result["resourceID"] != oldID {
				continue
			}
			text := strings.ReplaceAll(string(mustJSON(t, result)), oldID, newID)
			doc["results"] = append(doc["results"].([]any), map[string]any(decodeScan(t, []byte(text))))
		}
	}
	return doc
}

// withoutResults drops the result entries of the given resource IDs, as a
// scan whose resources carry no findings does.
func (d scanDoc) withoutResults(t *testing.T, ids map[string]bool) scanDoc {
	t.Helper()
	doc := decodeScan(t, d.encode(t))
	var results []any
	for _, raw := range doc["results"].([]any) {
		if !ids[raw.(map[string]any)["resourceID"].(string)] {
			results = append(results, raw)
		}
	}
	doc["results"] = results
	return doc
}

// without is the scan after file was deleted.
func (d scanDoc) without(t *testing.T, file string) scanDoc {
	t.Helper()
	gone := map[string]bool{}
	for _, resource := range d.resourcesAt(file) {
		gone[resource["resourceID"].(string)] = true
	}
	doc := decodeScan(t, d.encode(t))
	var resources, results []any
	for _, raw := range doc["resources"].([]any) {
		if !gone[raw.(map[string]any)["resourceID"].(string)] {
			resources = append(resources, raw)
		}
	}
	for _, raw := range doc["results"].([]any) {
		if !gone[raw.(map[string]any)["resourceID"].(string)] {
			results = append(results, raw)
		}
	}
	doc["resources"], doc["results"] = resources, results
	return doc
}

// edited changes the content of the resources in a file, as editing the
// manifest does.
func (d scanDoc) edited(t *testing.T, file string, edit func(object map[string]any)) scanDoc {
	t.Helper()
	doc := decodeScan(t, d.encode(t))
	for _, resource := range doc.resourcesAt(file) {
		edit(resource["object"].(map[string]any))
	}
	return doc
}

// withImage is an edit that gives the first container another image.
func withImage(image string) func(map[string]any) {
	return func(object map[string]any) {
		spec := object["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
		spec["containers"].([]any)[0].(map[string]any)["image"] = image
	}
}

// evidenceMoved rewrites the evidence of one resource's findings, as a manifest
// changed so that the field they point at is another one.
func (d scanDoc) evidenceMoved(t *testing.T, resourceSuffix string, old, replacement string) scanDoc {
	t.Helper()
	doc := decodeScan(t, d.encode(t))
	results := doc["results"].([]any)
	for i, raw := range results {
		result := raw.(map[string]any)
		if strings.HasSuffix(result["resourceID"].(string), resourceSuffix) {
			before := string(mustJSON(t, result))
			after := strings.ReplaceAll(before, old, replacement)
			require.NotEqual(t, before, after, "the edit changed nothing: %q is not in the findings of %s", old, resourceSuffix)
			results[i] = map[string]any(decodeScan(t, []byte(after)))
		}
	}
	return doc
}

// evidencePointsAt makes the findings of a resource whose evidence path contains
// pathPart name another resource as their evidence.
func (d scanDoc) evidencePointsAt(t *testing.T, resourceSuffix, pathPart, evidenceID string) scanDoc {
	t.Helper()
	doc := decodeScan(t, d.encode(t))
	changed := 0
	for _, raw := range doc["results"].([]any) {
		result := raw.(map[string]any)
		if !strings.HasSuffix(result["resourceID"].(string), resourceSuffix) {
			continue
		}
		for _, control := range result["controls"].([]any) {
			rules, _ := control.(map[string]any)["rules"].([]any)
			for _, rule := range rules {
				paths, _ := rule.(map[string]any)["paths"].([]any)
				for _, entry := range paths {
					path := entry.(map[string]any)
					fix, _ := path["fixPath"].(map[string]any)
					if fixed, _ := fix["path"].(string); strings.Contains(fixed, pathPart) {
						path["resourceID"] = evidenceID
						changed++
					}
				}
			}
		}
	}
	require.NotZero(t, changed, "no finding of %s has evidence at %q", resourceSuffix, pathPart)
	return doc
}

// withControlPassing makes a control pass on a resource, as fixing what it found
// does: no failed rule, no evidence.
func (d scanDoc) withControlPassing(t *testing.T, resourceSuffix, controlID string) scanDoc {
	t.Helper()
	doc := decodeScan(t, d.encode(t))
	changed := 0
	for _, raw := range doc["results"].([]any) {
		result := raw.(map[string]any)
		if !strings.HasSuffix(result["resourceID"].(string), resourceSuffix) {
			continue
		}
		for _, control := range result["controls"].([]any) {
			c := control.(map[string]any)
			if c["controlID"] != controlID {
				continue
			}
			c["status"] = map[string]any{"status": "passed"}
			for _, rule := range c["rules"].([]any) {
				r := rule.(map[string]any)
				r["status"] = "passed"
				delete(r, "paths")
			}
			changed++
		}
	}
	require.NotZero(t, changed, "%s has no control %s", resourceSuffix, controlID)
	return doc
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	require.NoError(t, err)
	return raw
}

func classifyDocs(t *testing.T, base, head scanDoc) *Result {
	t.Helper()
	result, err := Classify(base.encode(t), head.encode(t), diff.Options{})
	require.NoError(t, err)
	return result
}

// findingsOn counts the findings in a list that are on a resource.
func findingsOn(changes []diff.ControlChange, identity string) int {
	n := 0
	for _, change := range changes {
		if change.ResourceID == identity {
			n++
		}
	}
	return n
}

func renamedOn(findings []RenamedFinding, identity string) int {
	n := 0
	for _, finding := range findings {
		if finding.Finding.ResourceID == identity {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------

func TestClassifyUnchangedScan(t *testing.T) {
	t.Parallel()
	result := classifyDocs(t, loadScan(t, "two_files"), loadScan(t, "two_files"))

	assert.NotEmpty(t, result.Existing)
	assert.Empty(t, result.New)
	assert.Empty(t, result.Changed)
	assert.Empty(t, result.Resolved)
	assert.Empty(t, result.Removed)
	assert.Empty(t, result.Renamed)
	assert.Empty(t, result.Renames)
	assert.Empty(t, result.Incomparable)
}

func TestClassifyNewResource(t *testing.T) {
	t.Parallel()
	base := loadScan(t, "two_files")
	head := base.copied(t, "b.yaml", "c.yaml", "worker", 5000011) // a manifest with findings of its own
	const worker = "c.yaml::apps/v1::default::Deployment::worker"

	result := classifyDocs(t, base, head)

	assert.Equal(t, findingsOn(classifyDocs(t, base, base).Existing, backendInB), findingsOn(result.New, worker), "every finding of the new resource is new")
	assert.NotZero(t, findingsOn(result.New, worker))
	assert.Empty(t, result.Removed)
	assert.Empty(t, result.Resolved)
	assert.Empty(t, result.Renames)
	assert.Equal(t, len(classifyDocs(t, base, base).Existing), len(result.Existing), "what was there is unchanged")
}

func TestClassifyModifiedResource(t *testing.T) {
	t.Parallel()
	// A real edit of the frontend that fixed one finding, with a ConfigMap added
	// above it so that every position in the file moved.
	result, err := Classify(fixture(t, "base"), fixture(t, "edited_and_prepended"), diff.Options{})
	require.NoError(t, err)

	assert.NotEmpty(t, result.Resolved, "the finding the edit fixed")
	for _, change := range result.Resolved {
		assert.Equal(t, "multi.yaml::apps/v1::default::Deployment::frontend", change.ResourceID)
	}
	assert.Empty(t, result.New)
	assert.Empty(t, result.Removed, "a modified resource is still there")
	assert.Empty(t, result.Renames, "a modified resource keeps its identity: it was not moved")
	assert.NotZero(t, findingsOn(result.Existing, "multi.yaml::apps/v1::default::Deployment::backend"), "the resource that was not edited")
}

func TestClassifyNewlyIntroducedFinding(t *testing.T) {
	t.Parallel()
	// The edit undone: the finding it had fixed is back.
	result, err := Classify(fixture(t, "edited_and_prepended"), fixture(t, "base"), diff.Options{})
	require.NoError(t, err)

	assert.NotEmpty(t, result.New)
	for _, change := range result.New {
		assert.Equal(t, "multi.yaml::apps/v1::default::Deployment::frontend", change.ResourceID)
	}
	assert.Empty(t, result.Resolved)
}

func TestClassifyRemovedResource(t *testing.T) {
	t.Parallel()
	// The first document of the file was deleted.
	result, err := Classify(fixture(t, "base"), fixture(t, "first_removed"), diff.Options{})
	require.NoError(t, err)

	frontend := "multi.yaml::apps/v1::default::Deployment::frontend"
	was, err := Classify(fixture(t, "base"), fixture(t, "base"), diff.Options{})
	require.NoError(t, err)
	assert.NotZero(t, findingsOn(was.Existing, frontend))
	assert.Equal(t, findingsOn(was.Existing, frontend), findingsOn(result.Removed, frontend), "all its findings are removed with it")
	assert.Empty(t, result.Resolved, "a removed resource's findings are not resolved ones")
	assert.Empty(t, result.Renames)
	assert.Empty(t, result.Renamed)
	assert.NotZero(t, findingsOn(result.Existing, "multi.yaml::apps/v1::default::Deployment::backend"))
}

func TestClassifyRenamedResource(t *testing.T) {
	t.Parallel()
	base := loadScan(t, "two_files")
	head := base.renamed(t, "a.yaml", "renamed.yaml")
	unchanged := classifyDocs(t, base, base)

	result := classifyDocs(t, base, head)

	assert.Equal(t, []Rename{{From: frontendInA, To: frontendMoved}}, result.Renames)
	assert.Equal(t, findingsOn(unchanged.Existing, frontendInA), renamedOn(result.Renamed, frontendMoved), "every finding of the resource moved with it")
	for _, finding := range result.Renamed {
		assert.Equal(t, frontendInA, finding.From)
	}
	assert.Empty(t, result.New, "a moved resource is not new")
	assert.Empty(t, result.Removed, "and is not removed")
	assert.Empty(t, result.Resolved)
	assert.Equal(t, findingsOn(unchanged.Existing, backendInB), findingsOn(result.Existing, backendInB), "the other resource is untouched")
}

func TestClassifyRenameWithEvidencePointingAtARenamedResource(t *testing.T) {
	t.Parallel()
	// A finding of the frontend names the backend as its evidence. The backend
	// moves; the frontend does not, and nothing about the finding changed.
	base := loadScan(t, "two_files")
	backendID := base.resourcesAt("b.yaml")[0]["resourceID"].(string)
	base = base.evidencePointsAt(t, "/frontend", "runAsNonRoot", backendID)
	head := base.renamed(t, "b.yaml", "moved-backend.yaml")

	result := classifyDocs(t, base, head)

	require.Len(t, result.Renames, 1)
	assert.Equal(t, backendInB, result.Renames[0].From)
	var evidenced []diff.ControlChange
	for _, change := range result.Existing {
		if change.EvidenceResourceID != "" && change.ResourceID == frontendInA {
			evidenced = append(evidenced, change)
		}
	}
	assert.NotEmpty(t, evidenced, "the finding that points at the moved resource is an existing one")
	for _, change := range result.Resolved {
		assert.NotEqual(t, frontendInA, change.ResourceID, "it is not resolved")
	}
	for _, change := range result.New {
		assert.NotEqual(t, frontendInA, change.ResourceID, "and it is not new")
	}
}

func TestClassifyDeletedAndCreatedAgainWithOtherContentIsNotARename(t *testing.T) {
	t.Parallel()
	base := loadScan(t, "two_files")
	// a.yaml is deleted, and a manifest of the same name, another image, is made
	// in a new file: not the same resource, however alike.
	head := base.copied(t, "a.yaml", "c.yaml", "", 7000019).without(t, "a.yaml").edited(t, "c.yaml", withImage("nginx:1.27"))
	unchanged := classifyDocs(t, base, base)

	result := classifyDocs(t, base, head)

	assert.Empty(t, result.Renames)
	assert.Empty(t, result.Renamed)
	assert.Equal(t, findingsOn(unchanged.Existing, frontendInA), findingsOn(result.Removed, frontendInA), "the old resource's findings are removed")
	assert.Equal(t, findingsOn(unchanged.Existing, frontendInA), findingsOn(result.New, "c.yaml::apps/v1::default::Deployment::frontend"), "and the new one's are new")
}

func TestClassifyRenamedResourceKeepsTheDifferencesBetweenItsFindings(t *testing.T) {
	t.Parallel()
	base := loadScan(t, "two_files")
	unchanged := classifyDocs(t, base, base)

	t.Run("a finding that was fixed as the file moved", func(t *testing.T) {
		t.Parallel()
		head := base.renamed(t, "a.yaml", "renamed.yaml").withControlPassing(t, "/frontend", "C-0057")

		result := classifyDocs(t, base, head)

		fixed := 0
		for _, change := range unchanged.Existing {
			if change.ResourceID == frontendInA && change.ControlID == "C-0057" {
				fixed++
			}
		}
		require.NotZero(t, fixed)
		assert.Equal(t, []Rename{{From: frontendInA, To: frontendMoved}}, result.Renames)
		assert.Equal(t, fixed, findingsOn(result.Removed, frontendInA), "the fixed finding is not lost: it stays removed")
		assert.Equal(t, findingsOn(unchanged.Existing, frontendInA)-fixed, renamedOn(result.Renamed, frontendMoved), "the others moved with the resource")
		for _, finding := range result.Renamed {
			assert.NotEqual(t, "C-0057", finding.Finding.ControlID)
		}
		assert.Empty(t, result.New)
	})

	t.Run("a finding that appeared as the file moved", func(t *testing.T) {
		t.Parallel()
		// The same pair of scans the other way round: the finding is new.
		fixedBase := base.withControlPassing(t, "/frontend", "C-0057")
		head := base.renamed(t, "a.yaml", "renamed.yaml")

		result := classifyDocs(t, fixedBase, head)

		assert.Equal(t, []Rename{{From: frontendInA, To: frontendMoved}}, result.Renames)
		assert.NotZero(t, findingsOn(result.New, frontendMoved), "the finding that appeared is not lost: it is new")
		for _, change := range result.New {
			assert.Equal(t, "C-0057", change.ControlID)
		}
		assert.Empty(t, result.Removed)
	})
}

func TestClassifyRenamedAndEditedAtOnceIsNotARename(t *testing.T) {
	t.Parallel()
	base := loadScan(t, "two_files")
	head := base.renamed(t, "a.yaml", "renamed.yaml").edited(t, "renamed.yaml", withImage("nginx:1.27"))

	result := classifyDocs(t, base, head)

	assert.Empty(t, result.Renames, "a moved resource that also changed cannot be told from one deleted and another made")
	assert.NotEmpty(t, result.Removed)
	assert.NotEmpty(t, result.New)
	assert.Empty(t, result.Renamed)
}

func TestClassifyAmbiguousRenameCandidatesStaySeparate(t *testing.T) {
	t.Parallel()
	base := loadScan(t, "two_files")
	unchanged := classifyDocs(t, base, base)
	frontend := findingsOn(unchanged.Existing, frontendInA)

	t.Run("one resource gone and two identical ones appear", func(t *testing.T) {
		t.Parallel()
		head := base.renamed(t, "a.yaml", "x.yaml").copied(t, "x.yaml", "y.yaml", "", 9000007)

		result := classifyDocs(t, base, head)

		assert.Empty(t, result.Renames)
		assert.Empty(t, result.Renamed)
		assert.Equal(t, frontend, findingsOn(result.Removed, frontendInA), "nothing is lost: it is removed here")
		assert.Equal(t, frontend, findingsOn(result.New, "x.yaml::apps/v1::default::Deployment::frontend"), "and new there")
		assert.Equal(t, frontend, findingsOn(result.New, "y.yaml::apps/v1::default::Deployment::frontend"))
		assert.NotEmpty(t, result.Warnings)
		assert.Contains(t, strings.Join(result.Warnings, "\n"), "not treated as renamed")
	})

	t.Run("two identical resources gone and one appears", func(t *testing.T) {
		t.Parallel()
		twin := base.copied(t, "a.yaml", "twin.yaml", "", 9100009) // the same manifest in two files
		head := twin.without(t, "twin.yaml").renamed(t, "a.yaml", "x.yaml").without(t, "twin.yaml")

		result := classifyDocs(t, twin, head)

		assert.Empty(t, result.Renames)
		assert.Empty(t, result.Renamed)
		assert.NotEmpty(t, result.Warnings)
	})

	t.Run("the name is also borne by a resource that stays", func(t *testing.T) {
		t.Parallel()
		twin := base.copied(t, "a.yaml", "twin.yaml", "", 9200011)
		head := twin.renamed(t, "a.yaml", "x.yaml") // a.yaml moved; twin.yaml, the same manifest, stayed

		result := classifyDocs(t, twin, head)

		assert.Empty(t, result.Renames, "which of the two moved is a guess")
		assert.Equal(t, frontend, findingsOn(result.Removed, frontendInA))
		assert.Equal(t, frontend, findingsOn(result.New, "x.yaml::apps/v1::default::Deployment::frontend"))
	})
}

func TestClassifyRenamesAreNotLookedForWhenAResourceCannotBeIdentified(t *testing.T) {
	t.Parallel()
	base := loadScan(t, "two_files")
	// The backend's resource no longer says which file it came from, in either scan.
	for _, resource := range base.resourcesAt("b.yaml") {
		delete(resource, "source")
	}
	head := decodeScan(t, base.encode(t)).renamed(t, "a.yaml", "renamed.yaml")

	result := classifyDocs(t, base, head)

	assert.Empty(t, result.Renames, "the unidentified resource may be the one that moved")
	assert.Empty(t, result.Renamed)
	assert.Contains(t, strings.Join(result.Warnings, "\n"), "renamed files were not looked for")
	// The engine, which cannot tell whether the unidentified resource is the one
	// that moved, already keeps the findings of the same controls from being
	// called removed or new: they are incomparable, with the reason.
	assert.Empty(t, result.Removed)
	assert.Empty(t, result.New)
	assert.NotZero(t, findingsOn(result.Incomparable, frontendInA)+findingsOn(result.Incomparable, frontendMoved))
}

func TestClassifyRenamesAreNotLookedForWhenAnUnidentifiedResourceHasNoResult(t *testing.T) {
	t.Parallel()
	base := loadScan(t, "two_files")
	// The backend's resource no longer says which file it came from, in either
	// scan, and it has no result entry either, so Canonicalize never records
	// it as ambiguous: the snapshot must still treat the scan as unidentified,
	// or the frontend's move is reported as a rename it may not be.
	backendIDs := map[string]bool{}
	for _, resource := range base.resourcesAt("b.yaml") {
		backendIDs[resource["resourceID"].(string)] = true
		delete(resource, "source")
	}
	base = base.withoutResults(t, backendIDs)
	head := decodeScan(t, base.encode(t)).renamed(t, "a.yaml", "renamed.yaml")

	result := classifyDocs(t, base, head)

	assert.Empty(t, result.Renames, "the result-free unidentified resource may be the one that moved")
	assert.Empty(t, result.Renamed)
	assert.Contains(t, strings.Join(result.Warnings, "\n"), "renamed files were not looked for")
}

func TestClassifyChangedFinding(t *testing.T) {
	t.Parallel()
	base := loadScan(t, "two_files")

	t.Run("one finding whose evidence moved", func(t *testing.T) {
		t.Parallel()
		// The field a finding points at is another one now.
		head := base.evidenceMoved(t, "/frontend", `containers[0].securityContext.runAsNonRoot`, `containers[1].securityContext.runAsNonRoot`)

		result := classifyDocs(t, base, head)

		require.Len(t, result.Changed, 1)
		change := result.Changed[0]
		assert.Equal(t, frontendInA, change.Before.ResourceID)
		assert.Equal(t, change.Before.ControlID, change.After.ControlID)
		assert.Equal(t, change.Before.RuleName, change.After.RuleName)
		assert.Equal(t, change.Before.EvidenceType, change.After.EvidenceType)
		assert.Contains(t, change.Before.Path, "containers[0]")
		assert.Contains(t, change.After.Path, "containers[1]")
		for _, finding := range result.Resolved {
			assert.NotEqual(t, change.Before, finding, "it is one change, not also a resolved finding")
		}
		for _, finding := range result.New {
			assert.NotEqual(t, change.After, finding, "nor also a new one")
		}
	})

	t.Run("several findings moved at once are not paired", func(t *testing.T) {
		t.Parallel()
		// Two findings of the same control and kind move together: which went where
		// is not known, so they stay as resolved and new.
		head := base.evidenceMoved(t, "/frontend", `containers[0].securityContext.runAs`, `containers[1].securityContext.runAs`)

		result := classifyDocs(t, base, head)

		assert.Empty(t, result.Changed)
		assert.GreaterOrEqual(t, findingsOn(result.Resolved, frontendInA), 2)
		assert.GreaterOrEqual(t, findingsOn(result.New, frontendInA), 2)
	})
}

func TestClassifyIncompleteCoverageNeverMakesAFindingResolvedOrRemoved(t *testing.T) {
	t.Parallel()
	// The head scan could not load b.yaml (invalid YAML): the manifest was
	// skipped, as the scan's own coverage records.
	result, err := Classify(fixture(t, "two_files"), fixture(t, "two_files_one_invalid"), diff.Options{})
	require.NoError(t, err)

	assert.Empty(t, result.Removed, "a resource that was not evaluated is not a removed one")
	assert.Empty(t, result.Resolved)
	assert.Empty(t, result.Renames)
	assert.NotZero(t, findingsOn(result.Incomparable, backendInB), "its findings are incomparable, with the reason")
	for _, change := range result.Incomparable {
		assert.NotEmpty(t, change.Reason)
	}
	assert.NotZero(t, findingsOn(result.Existing, frontendInA), "what was read is still compared")
}

func TestClassifyTheSameDeletionIsRemovedOnlyByACompleteScan(t *testing.T) {
	t.Parallel()
	base := loadScan(t, "two_files")
	deleted := base.without(t, "b.yaml")

	complete := classifyDocs(t, completeScan(t, base), completeScan(t, deleted))
	assert.NotEmpty(t, complete.Removed, "the file is gone and the scan covered everything")
	assert.Empty(t, complete.Incomparable)

	gap := completeScan(t, deleted)
	gap["scanCoverage"].(map[string]any)["skippedManifests"] = []any{map[string]any{"path": "b.yaml", "reason": "invalid YAML"}}
	gap["scanCoverage"].(map[string]any)["degraded"] = true
	incomplete := classifyDocs(t, completeScan(t, base), gap)
	assert.Empty(t, incomplete.Removed, "with a manifest skipped, the same deletion cannot be told from a manifest that could not be read")
	assert.NotEmpty(t, incomplete.Incomparable)
}

func TestClassifyIsDeterministic(t *testing.T) {
	t.Parallel()
	base := loadScan(t, "two_files")
	head := base.renamed(t, "a.yaml", "renamed.yaml").evidenceMoved(t, "/backend", `containers[0].securityContext.runAsNonRoot`, `containers[1].securityContext.runAsNonRoot`)
	first := classifyDocs(t, base, head)
	for i := 0; i < 20; i++ {
		assert.Equal(t, first, classifyDocs(t, base, head))
	}
}

func TestClassifyEveryChangeIsReportedOnce(t *testing.T) {
	t.Parallel()
	// Sorting the engine's changes into more lists must not lose or repeat one.
	base := loadScan(t, "two_files")
	head := base.renamed(t, "a.yaml", "renamed.yaml").edited(t, "b.yaml", withImage("nginx:1.27")).
		evidenceMoved(t, "/backend", `containers[0].securityContext.runAsNonRoot`, `containers[1].securityContext.runAsNonRoot`)

	comparison, err := Compare(base.encode(t), head.encode(t), diff.Options{})
	require.NoError(t, err)
	result := classifyDocs(t, base, head)

	engine := len(comparison.ChangeSet.New) + len(comparison.ChangeSet.Resolved) + len(comparison.ChangeSet.Unchanged) + len(comparison.ChangeSet.Incomparable) + len(comparison.Removed)
	ours := len(result.New) + len(result.Resolved) + len(result.Existing) + len(result.Incomparable) + len(result.Removed) + 2*len(result.Changed) + 2*len(result.Renamed)
	assert.Equal(t, engine, ours, "the engine's changes and ours are the same set: a pair stands for two")
}

// completeScan gives a report the coverage of a scan that read and evaluated
// everything, as a real scan records it.
func completeScan(t *testing.T, doc scanDoc) scanDoc {
	t.Helper()
	copied := decodeScan(t, doc.encode(t))
	controls := 0
	if results, ok := copied["results"].([]any); ok && len(results) > 0 {
		controls = len(results[0].(map[string]any)["controls"].([]any))
	}
	if controls == 0 {
		controls = 60
	}
	copied["scanCoverage"] = map[string]any{
		"coverageScore":     100,
		"evaluatedControls": controls,
		"totalControls":     controls,
		"degraded":          false,
	}
	return copied
}

func TestClassifyChangedFindingWhoseEvidenceResourceMovedToo(t *testing.T) {
	t.Parallel()
	// A finding of the frontend names the backend as its evidence.
	base := loadScan(t, "two_files")
	backendID := base.resourcesAt("b.yaml")[0]["resourceID"].(string)
	base = base.evidencePointsAt(t, "/frontend", "runAsNonRoot", backendID)
	const backendMoved = "moved-backend.yaml::apps/v1::default::Deployment::backend"
	moveField := func(doc scanDoc) scanDoc {
		return doc.evidenceMoved(t, "/frontend", `containers[0].securityContext.runAsNonRoot`, `containers[1].securityContext.runAsNonRoot`)
	}

	t.Run("the evidence moved to another file and the finding to another field", func(t *testing.T) {
		t.Parallel()
		head := moveField(base.renamed(t, "b.yaml", "moved-backend.yaml"))

		result := classifyDocs(t, base, head)

		require.Equal(t, []Rename{{From: backendInB, To: backendMoved}}, result.Renames)
		require.NotEmpty(t, result.Changed, "it is one finding that moved, not one resolved and one new")
		for _, change := range result.Changed {
			assert.Equal(t, frontendInA, change.Before.ResourceID)
			assert.Equal(t, backendInB, change.Before.EvidenceResourceID)
			assert.Equal(t, backendMoved, change.After.EvidenceResourceID)
			assert.Contains(t, change.Before.Path, "containers[0]")
			assert.Contains(t, change.After.Path, "containers[1]")
		}
		assert.Zero(t, findingsOn(result.Resolved, frontendInA), "none is also a resolved finding")
		assert.Zero(t, findingsOn(result.New, frontendInA), "nor also a new one")
	})

	t.Run("the evidence did not move", func(t *testing.T) {
		t.Parallel()
		result := classifyDocs(t, base, moveField(base))

		assert.Empty(t, result.Renames)
		require.NotEmpty(t, result.Changed)
		for _, change := range result.Changed {
			assert.Equal(t, backendInB, change.Before.EvidenceResourceID)
			assert.Equal(t, backendInB, change.After.EvidenceResourceID)
		}
		assert.Zero(t, findingsOn(result.Resolved, frontendInA))
		assert.Zero(t, findingsOn(result.New, frontendInA))
	})

	t.Run("the evidence moved and the finding now points at another resource", func(t *testing.T) {
		t.Parallel()
		// A different evidence resource is a real difference, not the rename.
		head := moveField(base.renamed(t, "b.yaml", "moved-backend.yaml")).
			evidencePointsAt(t, "/frontend", "containers[1].securityContext.runAsNonRoot", base.resourcesAt("a.yaml")[0]["resourceID"].(string))

		result := classifyDocs(t, base, head)

		assert.Empty(t, result.Changed)
		assert.NotZero(t, findingsOn(result.Resolved, frontendInA))
		assert.NotZero(t, findingsOn(result.New, frontendInA))
	})
}

func TestClassifyRenamesAreNotLookedForWhenAManifestWasSkipped(t *testing.T) {
	t.Parallel()
	full := loadScan(t, "two_files")
	// moved is the scan with the frontend in x.yaml instead of a.yaml.
	moved := full.renamed(t, "a.yaml", "x.yaml")
	skipping := func(doc scanDoc) scanDoc {
		doc = completeScan(t, doc)
		coverage := doc["scanCoverage"].(map[string]any)
		coverage["skippedManifests"] = []any{map[string]any{"path": "a.yaml", "reason": "invalid YAML"}}
		coverage["degraded"] = true
		return doc
	}
	const warning = "renamed files were not looked for"

	t.Run("the earlier scan skipped a manifest", func(t *testing.T) {
		t.Parallel()
		// a.yaml could not be loaded, so the frontend is not in the earlier scan;
		// an identical one is in x.yaml, which the later scan no longer has.
		result := classifyDocs(t, skipping(moved), completeScan(t, full))

		assert.Empty(t, result.Renames)
		assert.Empty(t, result.Renamed)
		assert.Contains(t, strings.Join(result.Warnings, "\n"), warning)
		assert.Contains(t, strings.Join(result.Warnings, "\n"), "base scan")
	})

	t.Run("the later scan skipped a manifest", func(t *testing.T) {
		t.Parallel()
		result := classifyDocs(t, completeScan(t, full), skipping(moved))

		assert.Empty(t, result.Renames)
		assert.Empty(t, result.Renamed)
		assert.Contains(t, strings.Join(result.Warnings, "\n"), warning)
		assert.Contains(t, strings.Join(result.Warnings, "\n"), "head scan")
	})

	t.Run("complete scans still find the rename", func(t *testing.T) {
		t.Parallel()
		result := classifyDocs(t, completeScan(t, full), completeScan(t, moved))

		assert.Equal(t, []Rename{{From: frontendInA, To: "x.yaml::apps/v1::default::Deployment::frontend"}}, result.Renames)
		assert.NotEmpty(t, result.Renamed)
		assert.NotContains(t, strings.Join(result.Warnings, "\n"), warning)
	})

	t.Run("an unidentified resource is still what is reported", func(t *testing.T) {
		t.Parallel()
		base := skipping(full)
		for _, resource := range base.resourcesAt("b.yaml") {
			delete(resource, "source")
		}
		head := decodeScan(t, base.encode(t))

		result := classifyDocs(t, base, head)

		assert.Empty(t, result.Renames)
		assert.Contains(t, strings.Join(result.Warnings, "\n"), "could not be identified")
	})
}
