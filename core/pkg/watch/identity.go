// Package watch holds the report comparison that "scan --watch" builds on.
//
// A local manifest scan names each resource by a positional ID: inserting or
// deleting a document in a multi-document file shifts the IDs of every
// resource after it, so two scans of the same directory cannot be compared by
// resource ID without reporting findings as new or resolved that did not
// change. This package rewrites those IDs to an identity derived from the file
// and the object itself before the reports are handed to the diff engine.
package watch

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

const (
	identitySeparator = "::"
	// emptyNamespace stands in for an object without metadata.namespace. It is
	// not a valid namespace name, so it cannot collide with a real one.
	emptyNamespace = "_"
)

// ErrNoResourceIdentity is returned when a report holds results but none of the
// resources needed to derive identities, as with --omit-raw-resources.
var ErrNoResourceIdentity = errors.New("report has no resources to derive stable identities from; scan without --omit-raw-resources")

// CanonicalReport is a scan report whose resource IDs have been replaced by
// stable identities.
type CanonicalReport struct {
	// JSON is the report with every resource ID rewritten. Resources whose
	// identity is ambiguous are left out of it entirely.
	JSON []byte
	// Resources is the set of stable identities present in JSON.
	Resources map[string]struct{}
	// Ambiguous maps an identity that could not be matched safely to the
	// reason. For a resource that could not be identified at all the key is
	// its original resource ID.
	Ambiguous map[string]string
}

// Identity returns the stable identity of a resource, or "" when the report
// does not say which file or object it came from.
func Identity(relativePath string, object map[string]any) string {
	relativePath = filepath.ToSlash(strings.TrimSpace(relativePath))
	if relativePath == "" || object == nil {
		return ""
	}
	apiVersion, _ := object["apiVersion"].(string)
	kind, _ := object["kind"].(string)
	metadata, _ := object["metadata"].(map[string]any)
	name, _ := metadata["name"].(string)
	namespace, _ := metadata["namespace"].(string)
	if kind == "" || name == "" {
		return ""
	}
	if namespace == "" {
		namespace = emptyNamespace
	}
	return strings.Join([]string{relativePath, apiVersion, namespace, kind, name}, identitySeparator)
}

// Canonicalize rewrites the resource IDs of a scan report in JSON form to
// stable identities. Resource IDs are rewritten everywhere they feed finding
// comparison: results[].resourceID, resources[].resourceID, the evidence
// paths and the related-resource lists. Resources that share an identity, or
// whose identity or evidence cannot be established, are removed from the
// result and reported in Ambiguous, never matched arbitrarily.
func Canonicalize(reportJSON []byte) (*CanonicalReport, error) {
	var doc map[string]any
	decoder := json.NewDecoder(bytes.NewReader(reportJSON))
	decoder.UseNumber() // keep numbers such as scores byte-exact
	if err := decoder.Decode(&doc); err != nil {
		return nil, fmt.Errorf("invalid report JSON: %w", err)
	}
	if doc == nil {
		return nil, errors.New("invalid report: expected a JSON object")
	}
	results, _ := doc["results"].([]any)
	resources, _ := doc["resources"].([]any)
	if len(results) > 0 && len(resources) == 0 {
		return nil, ErrNoResourceIdentity
	}

	// Map each original ID to its identity, and find identities shared by
	// several resources.
	idToIdentity := make(map[string]string, len(resources))
	identityIDs := make(map[string][]string, len(resources))
	for _, raw := range resources {
		resource, _ := raw.(map[string]any)
		id, _ := resource["resourceID"].(string)
		if id == "" {
			continue
		}
		source, _ := resource["source"].(map[string]any)
		relativePath, _ := source["relativePath"].(string)
		object, _ := resource["object"].(map[string]any)
		identity := Identity(relativePath, object)
		if identity == "" {
			continue
		}
		idToIdentity[id] = identity
		identityIDs[identity] = append(identityIDs[identity], id)
	}

	out := &CanonicalReport{Resources: map[string]struct{}{}, Ambiguous: map[string]string{}}
	excluded := map[string]struct{}{} // original IDs left out of the output
	for identity, ids := range identityIDs {
		if len(ids) > 1 {
			out.Ambiguous[identity] = fmt.Sprintf("%d resources in the scan share this identity", len(ids))
			for _, id := range ids {
				excluded[id] = struct{}{}
			}
		}
	}

	keptResults := make([]any, 0, len(results))
	for _, raw := range results {
		result, _ := raw.(map[string]any)
		id, _ := result["resourceID"].(string)
		if _, skip := excluded[id]; skip {
			continue
		}
		if _, known := idToIdentity[id]; !known {
			out.Ambiguous[id] = "the report does not identify the file and object of this resource"
			excluded[id] = struct{}{}
			continue
		}
		if unknown := unidentifiedEvidenceID(result, idToIdentity, excluded); unknown != "" {
			out.Ambiguous[idToIdentity[id]] = fmt.Sprintf("its evidence refers to %q, which the report does not identify", unknown)
			excluded[id] = struct{}{}
			continue
		}
		keptResults = append(keptResults, result)
	}
	// Dropping a result for evidence reasons can leave other results whose
	// evidence points at it; those are checked on the second pass.
	for changed := true; changed; {
		changed = false
		remaining := keptResults[:0]
		for _, raw := range keptResults {
			result := raw.(map[string]any)
			id, _ := result["resourceID"].(string)
			if unknown := unidentifiedEvidenceID(result, idToIdentity, excluded); unknown != "" {
				out.Ambiguous[idToIdentity[id]] = fmt.Sprintf("its evidence refers to %q, which was left out as ambiguous", unknown)
				excluded[id] = struct{}{}
				changed = true
				continue
			}
			remaining = append(remaining, raw)
		}
		keptResults = remaining
	}

	for _, raw := range keptResults {
		result := raw.(map[string]any)
		rewriteIDs(result, idToIdentity)
		identity, _ := result["resourceID"].(string)
		out.Resources[identity] = struct{}{}
	}
	keptResources := make([]any, 0, len(resources))
	for _, raw := range resources {
		resource, _ := raw.(map[string]any)
		id, _ := resource["resourceID"].(string)
		if _, skip := excluded[id]; skip {
			continue
		}
		if identity, ok := idToIdentity[id]; ok {
			resource["resourceID"] = identity
			keptResources = append(keptResources, resource)
		}
	}
	doc["results"] = keptResults
	doc["resources"] = keptResources

	encoded, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("encode canonical report: %w", err)
	}
	out.JSON = encoded
	return out, nil
}

// unidentifiedEvidenceID returns the first resource ID that a result's
// evidence refers to which has no stable identity, or was excluded.
func unidentifiedEvidenceID(result map[string]any, idToIdentity map[string]string, excluded map[string]struct{}) string {
	var found string
	check := func(id string) {
		if found != "" || id == "" {
			return
		}
		if _, ok := idToIdentity[id]; !ok {
			found = id
			return
		}
		if _, skip := excluded[id]; skip {
			found = id
		}
	}
	controls, _ := result["controls"].([]any)
	for _, rawControl := range controls {
		control, _ := rawControl.(map[string]any)
		rules, _ := control["rules"].([]any)
		for _, rawRule := range rules {
			rule, _ := rawRule.(map[string]any)
			paths, _ := rule["paths"].([]any)
			for _, rawPath := range paths {
				path, _ := rawPath.(map[string]any)
				id, _ := path["resourceID"].(string)
				check(id)
			}
			related, _ := rule["relatedResourcesIDs"].([]any)
			for _, rawID := range related {
				id, _ := rawID.(string)
				check(id)
			}
		}
	}
	return found
}

// rewriteIDs replaces every resource ID in a result, at any depth, with its
// identity. Only the keys that carry resource IDs are touched.
func rewriteIDs(node any, idToIdentity map[string]string) {
	switch value := node.(type) {
	case map[string]any:
		for key, child := range value {
			switch {
			case key == "resourceID":
				if id, ok := child.(string); ok {
					if identity, known := idToIdentity[id]; known {
						value[key] = identity
					}
				}
			case key == "relatedResourcesIDs":
				if list, ok := child.([]any); ok {
					for i, rawID := range list {
						if id, ok := rawID.(string); ok {
							if identity, known := idToIdentity[id]; known {
								list[i] = identity
							}
						}
					}
				}
			default:
				rewriteIDs(child, idToIdentity)
			}
		}
	case []any:
		for _, child := range value {
			rewriteIDs(child, idToIdentity)
		}
	}
}

// sortedKeys returns the keys of m in order, for deterministic output.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
