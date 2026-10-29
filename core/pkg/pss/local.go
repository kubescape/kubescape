package pss

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	k8syaml "k8s.io/apimachinery/pkg/util/yaml"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8sjson "k8s.io/apimachinery/pkg/util/json"
)

// supportedKinds maps each Kubernetes resource kind whose PodSpec can be
// extracted and evaluated by the PSS library to its API group. Besides the
// cluster workload targets, local manifests may hold the other pod-template
// kinds that Pod Security Admission evaluates: ReplicationController and
// PodTemplate.
var supportedKinds = localSupportedKinds()

func localSupportedKinds() map[string]string {
	kinds := make(map[string]string, len(DefaultWorkloadTargets)+2)
	for _, t := range DefaultWorkloadTargets {
		kinds[t.Kind] = t.GVR.Group
	}
	kinds["ReplicationController"] = ""
	kinds["PodTemplate"] = ""
	return kinds
}

// isSupportedWorkload reports whether u is one of the supported workload
// kinds. Like Pod Security Admission, it matches the API group as well as the
// kind: a custom resource that reuses a built-in kind name, such as a Volcano
// batch.volcano.sh Job, is not that workload and keeps its pod templates
// elsewhere. A manifest whose apiVersion is missing or does not parse names no
// group, so it is matched by its kind alone.
func isSupportedWorkload(u *unstructured.Unstructured) bool {
	group, ok := supportedKinds[u.GetKind()]
	if !ok {
		return false
	}
	apiVersion := u.GetAPIVersion()
	if apiVersion == "" {
		return true
	}
	gv, err := schema.ParseGroupVersion(apiVersion)
	return err != nil || gv.Group == group
}

// ParseLocalWorkloads reads YAML/JSON files from the given paths and
// returns unstructured objects suitable for PSS evaluation. Each path
// may be a file or a directory (non-recursive). Multi-document YAML
// files (separated by "---") are supported.
// Consecutive JSON object records in a single document are supported too.
//
// Only objects whose Kind is in the supported workload set
// (Pod, PodTemplate, Deployment, DaemonSet, StatefulSet, ReplicaSet,
// ReplicationController, Job, CronJob) in its built-in API group are
// returned (an object whose apiVersion is missing or does not parse is matched
// by its kind alone); other kinds, and custom resources reusing one of those
// kind names, are silently skipped.
func ParseLocalWorkloads(paths []string) ([]unstructured.Unstructured, error) {
	workloads, err := ParseLocalWorkloadSources(paths)
	if err != nil {
		return nil, err
	}
	return localWorkloadObjects(workloads), nil
}

// LocalWorkload is a workload read from a local manifest, together with
// where in that manifest it was found.
type LocalWorkload struct {
	unstructured.Unstructured

	// Source is where the workload was read from, or nil when it did not
	// come from a file (such as manifests read from stdin).
	Source *Source
}

// Source locates a workload in a local manifest file.
type Source struct {
	// File is the manifest's path: the path that was given, or the path of
	// a file found in a given directory.
	File string

	// Line and Column are 1-based and point at the start of the YAML
	// document or JSON value holding the workload. A workload taken from a
	// List is located at the List.
	Line   int
	Column int
}

// ParseLocalWorkloadSources is ParseLocalWorkloads, but records the file and
// position each workload was read from.
func ParseLocalWorkloadSources(paths []string) ([]LocalWorkload, error) {
	var results []LocalWorkload
	for _, p := range paths {
		objs, err := parseLocalPath(p)
		if err != nil {
			return nil, err
		}
		results = append(results, objs...)
	}
	return results, nil
}

func localWorkloadObjects(workloads []LocalWorkload) []unstructured.Unstructured {
	if workloads == nil {
		return nil
	}
	objs := make([]unstructured.Unstructured, len(workloads))
	for i := range workloads {
		objs[i] = workloads[i].Unstructured
	}
	return objs
}

// parseLocalPath handles a single path: if it's a directory, list YAML/JSON
// files in it (non-recursive); if it's a file, parse it directly.
func parseLocalPath(p string) ([]LocalWorkload, error) {
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
func parseDirectory(dir string) ([]LocalWorkload, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("cannot read directory %q: %w", dir, err)
	}

	var results []LocalWorkload
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
func parseFile(path string) ([]LocalWorkload, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read file %q: %w", path, err)
	}
	return parseDocuments(data, path, path)
}

// parseMultiDoc splits data into YAML documents and decodes each one.
// The source parameter is used only for error messages.
func parseMultiDoc(data []byte, source string) ([]unstructured.Unstructured, error) {
	workloads, err := parseDocuments(data, source, "")
	if err != nil {
		return nil, err
	}
	return localWorkloadObjects(workloads), nil
}

// parseDocuments is parseMultiDoc, but records where each workload was found.
// file is the path the data was read from, recorded as each workload's
// Source, or empty when the data did not come from a file.
func parseDocuments(data []byte, source, file string) ([]LocalWorkload, error) {
	var results []LocalWorkload

	input := bytes.NewReader(data)
	buffered := bufio.NewReader(input)
	reader := k8syaml.NewYAMLReader(buffered)
	docIndex := 0
	// line is the 1-based line of data the next document starts on, and
	// consumed the number of bytes of data the reader has read. The reader
	// hands back every line it consumes, apart from a "---" that ends a
	// document, so each document starts where the previous read stopped.
	line, consumed := 1, 0
	for {
		docLine := line
		doc, err := reader.Read()
		read := len(data) - input.Len() - buffered.Buffered()
		line += bytes.Count(data[consumed:read], []byte("\n"))
		consumed = read
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
		// A YAML reader segment can contain a stream of JSON values. Decode
		// through EOF so neither later workloads nor trailing errors disappear.
		searchFrom := 0
		for recordIndex := 0; ; recordIndex++ {
			var raw json.RawMessage
			if err := decoder.Decode(&raw); err == io.EOF {
				break
			} else if err != nil {
				return nil, fmt.Errorf("decoding document %d record %d in %s: %w", docIndex, recordIndex, source, err)
			}
			if len(bytes.TrimSpace(raw)) == 0 {
				continue
			}
			var src *Source
			if file != "" {
				var offset int
				offset, searchFrom = recordOffset(doc, raw, searchFrom)
				src = &Source{File: file}
				src.Line, src.Column = position(doc, docLine, offset)
			}
			var object map[string]any
			if err := k8sjson.Unmarshal(raw, &object); err != nil {
				return nil, fmt.Errorf("decoding document %d record %d in %s: %w", docIndex, recordIndex, source, err)
			}
			// Only genuinely empty objects and null records may be skipped.
			// A populated manifest without a kind must not become a clean scan.
			if len(object) == 0 {
				continue
			}
			if kind, present := object["kind"]; present && kind != nil {
				if _, ok := kind.(string); !ok {
					return nil, fmt.Errorf("document %d record %d in %s: kind must be a string", docIndex, recordIndex, source)
				}
			}
			u := unstructured.Unstructured{Object: object}

			if u.GetKind() == "" {
				return nil, fmt.Errorf("document %d record %d in %s: kind is required", docIndex, recordIndex, source)
			}

			if listKind, isList := listEnvelopeKind(u.Object); isList {
				workloads, err := expandListEnvelope(&u, listKind)
				if err != nil {
					return nil, fmt.Errorf("document %d record %d in %s: %w", docIndex, recordIndex, source, err)
				}
				for _, w := range workloads {
					results = append(results, LocalWorkload{Unstructured: w, Source: src})
				}
			} else if isSupportedWorkload(&u) {
				results = append(results, LocalWorkload{Unstructured: u, Source: src})
			}
		}
		docIndex++
	}
	return results, nil
}

// recordOffset returns the offset in doc of a record the decoder returned as
// raw, and the offset to search for the next record from. A JSON record is
// decoded verbatim, so it is found where it starts. A YAML document is
// converted to JSON first and decodes to a single record, which is placed at
// the document's first line of content.
func recordOffset(doc, raw []byte, searchFrom int) (offset, next int) {
	if i := bytes.Index(doc[searchFrom:], raw); i >= 0 {
		offset = searchFrom + i
		return offset, offset + len(raw)
	}
	return contentOffset(doc), searchFrom
}

// contentOffset returns the offset of the first character of doc that is not
// whitespace and not part of a comment or a "---" document marker line.
func contentOffset(doc []byte) int {
	for offset := 0; offset < len(doc); {
		end := bytes.IndexByte(doc[offset:], '\n')
		if end < 0 {
			end = len(doc)
		} else {
			end += offset
		}
		line := doc[offset:end]
		content := bytes.TrimLeft(line, " \t\r")
		if len(content) > 0 && content[0] != '#' && !isDocumentMarker(line) {
			return end - len(content)
		}
		offset = end + 1
	}
	return 0
}

// isDocumentMarker reports whether line is a "---" document marker, as the
// YAML reader recognizes one: followed by nothing but spaces or a comment.
func isDocumentMarker(line []byte) bool {
	rest, found := bytes.CutPrefix(line, []byte("---"))
	if !found {
		return false
	}
	rest = bytes.TrimSpace(rest)
	return len(rest) == 0 || rest[0] == '#'
}

// position converts offset in doc, a document starting on line docLine, to a
// 1-based line and column.
func position(doc []byte, docLine, offset int) (line, column int) {
	before := doc[:offset]
	line = docLine + bytes.Count(before, []byte("\n"))
	column = offset - (bytes.LastIndexByte(before, '\n') + 1) + 1
	return line, column
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
	items, ok := itemsRaw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s.items must be an array", listKind)
	}
	// Validate before ToList and typed-list defaulting can replace an
	// unreadable kind. Generic Lists cannot supply a missing item kind.
	for i, raw := range items {
		item, ok := raw.(map[string]any)
		if !ok || item == nil {
			return nil, fmt.Errorf("%s.items[%d] is not a Kubernetes object", listKind, i)
		}
		kind, present := item["kind"]
		if present && kind != nil {
			if _, ok := kind.(string); !ok {
				return nil, fmt.Errorf("%s.items[%d]: kind must be a string", listKind, i)
			}
		}
		if listKind == "List" && (kind == nil || kind == "") {
			return nil, fmt.Errorf("%s.items[%d]: kind is required", listKind, i)
		}
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
		} else if isSupportedWorkload(&item) {
			results = append(results, item)
		}
	}
	return results, nil
}

// ParseLocalWorkloadsFromReader reads YAML/JSON from a reader (e.g., stdin)
// and returns unstructured objects suitable for PSS evaluation.
func ParseLocalWorkloadsFromReader(r io.Reader, source string) ([]unstructured.Unstructured, error) {
	workloads, err := ParseLocalWorkloadSourcesFromReader(r, source)
	if err != nil {
		return nil, err
	}
	return localWorkloadObjects(workloads), nil
}

// ParseLocalWorkloadSourcesFromReader is ParseLocalWorkloadsFromReader for
// callers that also handle file sources. A reader is not a file, so the
// workloads it returns have no Source.
func ParseLocalWorkloadSourcesFromReader(r io.Reader, source string) ([]LocalWorkload, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading from %s: %w", source, err)
	}
	return parseDocuments(data, source, "")
}
