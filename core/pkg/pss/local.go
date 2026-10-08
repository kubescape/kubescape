package pss

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	k8syaml "k8s.io/apimachinery/pkg/util/yaml"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// supportedKinds is the set of Kubernetes resource kinds whose PodSpec
// can be extracted and evaluated by the PSS library.
var supportedKinds = SupportedKinds()

// ParseLocalWorkloads reads YAML/JSON files from the given paths and
// returns unstructured objects suitable for PSS evaluation. Each path
// may be a file or a directory (non-recursive). Multi-document YAML
// files (separated by "---") are supported.
//
// Only objects whose Kind is in the supported workload set
// (Pod, Deployment, DaemonSet, StatefulSet, ReplicaSet, Job, CronJob)
// are returned; other kinds are silently skipped.
func ParseLocalWorkloads(paths []string) ([]unstructured.Unstructured, error) {
	var results []unstructured.Unstructured
	for _, p := range paths {
		objs, err := parseLocalPath(p)
		if err != nil {
			return nil, err
		}
		results = append(results, objs...)
	}
	return results, nil
}

// parseLocalPath handles a single path: if it's a directory, list YAML/JSON
// files in it (non-recursive); if it's a file, parse it directly.
func parseLocalPath(p string) ([]unstructured.Unstructured, error) {
	info, err := os.Stat(p)
	if err != nil {
		return nil, fmt.Errorf("cannot access %q: %w", p, err)
	}

	if info.IsDir() {
		return parseDirectory(p)
	}
	return parseFile(p)
}

// parseDirectory lists YAML and JSON files in a directory (non-recursive)
// and parses each one.
func parseDirectory(dir string) ([]unstructured.Unstructured, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("cannot read directory %q: %w", dir, err)
	}

	var results []unstructured.Unstructured
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext != ".yaml" && ext != ".yml" && ext != ".json" {
			continue
		}
		objs, err := parseFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		results = append(results, objs...)
	}
	return results, nil
}

// parseFile reads a single file and extracts all YAML/JSON documents from it,
// filtering to supported workload kinds.
func parseFile(path string) ([]unstructured.Unstructured, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read file %q: %w", path, err)
	}
	return parseMultiDoc(data, path)
}

// parseMultiDoc splits data into YAML documents and decodes each one.
// The source parameter is used only for error messages.
func parseMultiDoc(data []byte, source string) ([]unstructured.Unstructured, error) {
	var results []unstructured.Unstructured

	reader := k8syaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(data)))
	docIndex := 0
	for {
		doc, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading YAML document %d in %s: %w", docIndex, source, err)
		}

		// Skip empty documents (e.g., trailing "---")
		trimmed := bytes.TrimSpace(doc)
		if len(trimmed) == 0 {
			docIndex++
			continue
		}

		decoder := k8syaml.NewYAMLOrJSONDecoder(bytes.NewReader(doc), len(doc))
		var u unstructured.Unstructured
		if err := decoder.Decode(&u); err != nil {
			return nil, fmt.Errorf("decoding document %d in %s: %w", docIndex, source, err)
		}

		// Skip empty objects (malformed documents that decode to nothing)
		if u.Object == nil || u.GetKind() == "" {
			docIndex++
			continue
		}

		// Check for List / typed-list envelope (e.g. List, PodList)
		if listKind, isList := listEnvelopeKind(u.Object); isList {
			workloads, err := expandListEnvelope(&u, listKind)
			if err != nil {
				return nil, fmt.Errorf("document %d in %s: %w", docIndex, source, err)
			}
			results = append(results, workloads...)
		} else if supportedKinds[u.GetKind()] {
			results = append(results, u)
		}
		docIndex++
	}
	return results, nil
}

// listEnvelopeKind recognizes the canonical List kind and typed list
// envelopes such as PodList. A typed list has no resource identity of its own;
// requiring that property prevents a normal named CR such as AllowList from
// being classified as a list merely because its kind ends in "List".
func listEnvelopeKind(obj map[string]any) (string, bool) {
	kindValue, hasKind := obj["kind"]
	if !hasKind {
		return "", false
	}
	kind, ok := kindValue.(string)
	if !ok {
		return "", false
	}
	if kind == "List" {
		return kind, true
	}
	if strings.HasSuffix(kind, "List") && !manifestHasIdentity(obj) {
		return kind, true
	}
	return kind, false
}

func manifestHasIdentity(obj map[string]any) bool {
	metadata, ok := obj["metadata"].(map[string]any)
	if !ok {
		return false
	}
	for _, field := range []string{"name", "generateName"} {
		if value, ok := metadata[field].(string); ok && value != "" {
			return true
		}
	}
	return false
}

// restoreTypedListItemTypeMeta fills each missing field independently. The
// Kubernetes unstructured decoder only inherits the parent type metadata when
// both fields are absent, so an item that supplies just one of kind or
// apiVersion would otherwise remain only partially identified. Explicit item
// values remain authoritative.
func restoreTypedListItemTypeMeta(list *unstructured.UnstructuredList, listKind string) {
	if listKind == "List" {
		return
	}

	itemKind := strings.TrimSuffix(listKind, "List")
	listAPIVersion := list.GetAPIVersion()
	for i := range list.Items {
		if list.Items[i].GetKind() == "" {
			list.Items[i].SetKind(itemKind)
		}
		if list.Items[i].GetAPIVersion() == "" {
			list.Items[i].SetAPIVersion(listAPIVersion)
		}
	}
}

// expandListEnvelope unpacks a Kubernetes List or typed-list envelope (e.g. PodList),
// restoring item type metadata if omitted, and recursively unwrapping any nested lists.
func expandListEnvelope(u *unstructured.Unstructured, listKind string) ([]unstructured.Unstructured, error) {
	itemsRaw, ok := u.Object["items"]
	if !ok || itemsRaw == nil {
		return nil, fmt.Errorf("%s.items must be an array", listKind)
	}
	if _, ok := itemsRaw.([]any); !ok {
		return nil, fmt.Errorf("%s.items must be an array", listKind)
	}

	ulist, err := u.ToList()
	if err != nil {
		return nil, fmt.Errorf("decoding %s: %w", listKind, err)
	}

	restoreTypedListItemTypeMeta(ulist, listKind)

	var results []unstructured.Unstructured
	for i := range ulist.Items {
		item := ulist.Items[i]
		if item.Object == nil {
			return nil, fmt.Errorf("%s.items[%d] is not a Kubernetes object", listKind, i)
		}
		if nestedKind, isList := listEnvelopeKind(item.Object); isList {
			nestedWorkloads, err := expandListEnvelope(&item, nestedKind)
			if err != nil {
				return nil, fmt.Errorf("%s.items[%d]: %w", listKind, i, err)
			}
			results = append(results, nestedWorkloads...)
		} else if supportedKinds[item.GetKind()] {
			results = append(results, item)
		}
	}
	return results, nil
}

// ParseLocalWorkloadsFromReader reads YAML/JSON from a reader (e.g., stdin)
// and returns unstructured objects suitable for PSS evaluation.
func ParseLocalWorkloadsFromReader(r io.Reader, source string) ([]unstructured.Unstructured, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading from %s: %w", source, err)
	}
	return parseMultiDoc(data, source)
}
