package watch

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/kubescape/kubescape/v4/core/cautils"
)

// Rename is a resource that kept its content and moved to another file: the
// file was renamed or the document was moved. From and To are the resource's
// identities in the two scans (see Identity).
type Rename struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// objectKey is what a resource is called, apart from the file it is in.
type objectKey struct {
	apiVersion, namespace, kind, name string
}

func (k objectKey) String() string {
	return strings.Join([]string{k.apiVersion, k.namespace, k.kind, k.name}, "/")
}

type resourceInfo struct {
	key objectKey
	// fingerprint is a digest of the resource's content: the object as the scan
	// read it, less sourcePath. The scan records the file and the position in it
	// in that field, so it changes when a manifest moves, and a rename is a change
	// of exactly that and nothing else.
	fingerprint string
}

// snapshot is a canonicalized scan with what is needed to look for renames. It
// is built once per scan, so a baseline does not parse its report again for
// every comparison.
type snapshot struct {
	report *CanonicalReport
	// infos describes the resources that can be matched, by identity.
	infos map[string]resourceInfo
	// keys counts the resources that bear each key, those that can be matched and
	// those that were set aside as ambiguous.
	keys map[objectKey]int
	// unidentified is set when the scan holds a resource the report does not say
	// enough about to tell what it is.
	unidentified bool
	// skippedManifests is set when the scan could not load a manifest it found:
	// the resources in it are absent from the scan, though their files are there.
	skippedManifests bool
}

// newSnapshot canonicalizes a report and describes its resources.
func newSnapshot(reportJSON []byte) (*snapshot, error) {
	report, err := Canonicalize(reportJSON)
	if err != nil {
		return nil, err
	}
	snap := &snapshot{
		report: report,
		infos:  make(map[string]resourceInfo, len(report.Resources)),
		keys:   make(map[objectKey]int, len(report.Resources)),
	}

	var coverage struct {
		ScanCoverage *cautils.ScanCoverage `json:"scanCoverage"`
	}
	if err := json.Unmarshal(reportJSON, &coverage); err != nil {
		return nil, fmt.Errorf("read the scan coverage: %w", err)
	}
	snap.skippedManifests = coverage.ScanCoverage != nil && len(coverage.ScanCoverage.SkippedManifests) > 0

	var doc struct {
		Resources []struct {
			ResourceID string         `json:"resourceID"`
			Object     map[string]any `json:"object"`
		} `json:"resources"`
	}
	decoder := json.NewDecoder(bytes.NewReader(report.JSON))
	decoder.UseNumber() // a number in a manifest is compared as it was written
	if err := decoder.Decode(&doc); err != nil {
		return nil, fmt.Errorf("read the resources of the canonical report: %w", err)
	}
	for _, resource := range doc.Resources {
		if resource.ResourceID == "" || resource.Object == nil {
			continue
		}
		fingerprint, err := contentFingerprint(resource.Object)
		if err != nil {
			return nil, fmt.Errorf("resource %q: %w", resource.ResourceID, err)
		}
		info := resourceInfo{key: keyOfObject(resource.Object), fingerprint: fingerprint}
		snap.infos[resource.ResourceID] = info
		snap.keys[info.key]++
	}

	// A resource with no result entry never reaches Canonicalize's ambiguity
	// reporting: it has no result to set aside, so it is simply omitted, and
	// the snapshot never learns it could not be identified. It may still be
	// the resource that moved, so inspect the original resource list and mark
	// the snapshot unidentified whenever any resource cannot be assigned a
	// stable identity, regardless of whether it has findings.
	var original struct {
		Resources []struct {
			ResourceID string `json:"resourceID"`
			Source     struct {
				RelativePath string `json:"relativePath"`
			} `json:"source"`
			Object map[string]any `json:"object"`
		} `json:"resources"`
	}
	if err := json.Unmarshal(reportJSON, &original); err != nil {
		return nil, fmt.Errorf("read the original resources: %w", err)
	}
	for _, resource := range original.Resources {
		if resource.ResourceID == "" {
			continue
		}
		if Identity(resource.Source.RelativePath, resource.Object) == "" {
			snap.unidentified = true
			break
		}
	}

	// Resources set aside as ambiguous are not matched, but they are still
	// resources with a name: several can share one, so they count towards how
	// many bear it.
	for identity := range report.Ambiguous {
		key, ok := keyOfIdentity(identity)
		if !ok {
			snap.unidentified = true
			continue
		}
		// Most are identities that two or more resources share; counting two is
		// the least that keeps the name from being taken for a single resource's.
		snap.keys[key] += 2
	}
	return snap, nil
}

func keyOfObject(object map[string]any) objectKey {
	apiVersion, _ := object["apiVersion"].(string)
	kind, _ := object["kind"].(string)
	metadata, _ := object["metadata"].(map[string]any)
	name, _ := metadata["name"].(string)
	namespace, _ := metadata["namespace"].(string)
	if namespace == "" {
		namespace = emptyNamespace
	}
	return objectKey{apiVersion: apiVersion, namespace: namespace, kind: kind, name: name}
}

// keyOfIdentity reads the key out of an identity, which ends in
// apiVersion::namespace::kind::name after the path of the file. The path is
// taken from the front, as it is the part that could itself hold the separator.
func keyOfIdentity(identity string) (objectKey, bool) {
	parts := strings.Split(identity, identitySeparator)
	if len(parts) < 5 {
		return objectKey{}, false
	}
	tail := parts[len(parts)-4:]
	return objectKey{apiVersion: tail[0], namespace: tail[1], kind: tail[2], name: tail[3]}, true
}

// contentFingerprint digests an object without the field that says where it
// came from. The encoding sorts keys, so equal content gives an equal digest.
func contentFingerprint(object map[string]any) (string, error) {
	content := make(map[string]any, len(object))
	for field, value := range object {
		if field != "sourcePath" {
			content[field] = value
		}
	}
	encoded, err := json.Marshal(content)
	if err != nil {
		return "", fmt.Errorf("encode the resource: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

// detectRenames finds the resources that moved between two scans, and says why
// it did not pair a resource that looks as if it moved. It is conservative:
// moving is the only explanation it looks for, and it needs proof.
//
// A resource that is in the base scan and not in the head scan, under its
// identity, was renamed when a resource of the head scan that is not in the base
// scan has
//
//   - the same key, apiVersion, namespace, kind and name, and
//   - the same content, which is every field of the object but where it was read from,
//
// and the pair is the only possible one: the key is borne by one resource in
// each scan. Where the key is borne by several, whether in the files that moved
// or elsewhere, which one moved is a guess, and the resource stays removed in one
// place and new in the other. So does a resource whose content changed with its
// file, which cannot be told from one that was deleted and another created.
//
// Nothing is looked for in a scan with a resource that could not be identified:
// it may be the one that moved. Nor is it in a scan that skipped a manifest: the
// resources of a manifest that could not be loaded are absent from it, and an
// identical copy elsewhere would pass for the one that moved.
func detectRenames(base, head *snapshot) (renames []Rename, warnings []string) {
	if base.unidentified || head.unidentified {
		return nil, []string{"renamed files were not looked for: a resource in a scan could not be identified, so it cannot be told whether it is one that moved"}
	}

	if base.skippedManifests || head.skippedManifests {
		scan := "base"
		switch {
		case base.skippedManifests && head.skippedManifests:
			scan = "base and head"
		case head.skippedManifests:
			scan = "head"
		}
		return nil, []string{fmt.Sprintf("renamed files were not looked for: manifests were skipped in the %s scan, so a resource missing from it may not have moved or been removed", scan)}
	}

	appearedByKey := map[objectKey][]string{}
	for identity, info := range head.infos {
		if _, known := base.infos[identity]; !known {
			appearedByKey[info.key] = append(appearedByKey[info.key], identity)
		}
	}

	vanished := make([]string, 0)
	for identity := range base.infos {
		if _, known := head.infos[identity]; !known {
			vanished = append(vanished, identity)
		}
	}
	sort.Strings(vanished)

	for _, from := range vanished {
		info := base.infos[from]
		var same []string
		for _, candidate := range appearedByKey[info.key] {
			if head.infos[candidate].fingerprint == info.fingerprint {
				same = append(same, candidate)
			}
		}
		if len(same) == 0 {
			continue // nothing that looks like it: it was removed, or changed with its file
		}
		if len(same) != 1 || base.keys[info.key] != 1 || head.keys[info.key] != 1 {
			sort.Strings(same)
			warnings = append(warnings, fmt.Sprintf("resource %q was removed and %d resource(s) with the same name and content appear (%s), among %d and %d resources of that name: it is not known which, if any, was moved, so it is not treated as renamed",
				from, len(same), strings.Join(same, ", "), base.keys[info.key], head.keys[info.key]))
			continue
		}
		renames = append(renames, Rename{From: from, To: same[0]})
	}
	return renames, warnings
}
