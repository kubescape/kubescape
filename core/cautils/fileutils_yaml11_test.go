package cautils

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const pod11 = `apiVersion: v1
kind: Pod
metadata:
  name: p
  namespace: default
spec:
  containers:
    - name: c
      image: nginx
      securityContext:
        privileged: %s
        allowPrivilegeEscalation: %s
`

func podWith(privileged, ape string) []byte {
	return []byte(fmt.Sprintf(pod11, privileged, ape))
}

// kubectl reads yes/no as booleans, so a pod written that way must load as
// the same object as its true/false twin, without an error.
func TestReadYamlFileReadsYAML11BooleansLikeKubectl(t *testing.T) {
	for _, word := range [][2]string{{"yes", "no"}, {"Yes", "No"}, {"on", "off"}, {"y", "n"}, {"TRUE", "FALSE"}} {
		objs, err := readYamlFile(podWith(word[0], word[1]))
		require.NoError(t, err, word)
		require.Len(t, objs, 1)
		twin, err := readYamlFile(podWith("true", "false"))
		require.NoError(t, err)
		assert.Equal(t, twin[0].GetObject()["spec"], objs[0].GetObject()["spec"], word)
	}
}

// A document that is still invalid after the YAML 1.1 reading keeps today's
// behaviour: it is loaded as yaml.v3 read it and the error is reported.
func TestReadYamlFileKeepsErrorWhenYAML11ReadingIsStillInvalid(t *testing.T) {
	doc := []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: d
spec:
  replicas: "many"
  paused: yes
`)
	objs, err := readYamlFile(doc)
	require.Len(t, objs, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "structurally invalid")
	assert.Equal(t, "yes", objs[0].GetObject()["spec"].(map[string]any)["paused"])
}

// A document that is valid today must not be re-read: a quoted "yes" stays a
// string, and an unquoted yes in a free-form field is untouched.
func TestReadYamlFileLeavesValidDocumentsAlone(t *testing.T) {
	doc := []byte(`apiVersion: v1
kind: ConfigMap
metadata:
  name: cm
  annotations:
    enabled: "yes"
data:
  flag: "yes"
`)
	objs, err := readYamlFile(doc)
	require.NoError(t, err)
	require.Len(t, objs, 1)
	assert.Equal(t, "yes", objs[0].GetObject()["data"].(map[string]any)["flag"])
}

// A single-file scan and a directory scan must agree for these pods.
func TestLoadFilesYAML11SingleFileAndDirectoryAgree(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "pod.yaml")
	require.NoError(t, os.WriteFile(file, podWith("yes", "no"), 0o600))

	single, singleSkips, singleErrs := loadFiles(file, []string{file})
	assert.Empty(t, singleErrs)
	assert.Empty(t, singleSkips)
	require.Len(t, single[file], 1)

	other := filepath.Join(dir, "other.yaml")
	require.NoError(t, os.WriteFile(other, podWith("true", "false"), 0o600))
	multi, skips, errs := loadFiles(dir, []string{file, other})
	assert.Empty(t, errs)
	assert.Empty(t, skips)
	assert.Equal(t, multi[other][0].GetObject()["spec"], multi[file][0].GetObject()["spec"])
	assert.Equal(t, single[file][0].GetObject()["spec"], multi[file][0].GetObject()["spec"])
}

const podBigInt = `apiVersion: v1
kind: Pod
metadata:
  name: p
  namespace: default
spec:
  containers:
    - name: app
      securityContext:
        privileged: %s
        runAsUser: %s
`

func firstContainer(t *testing.T, doc []byte) map[string]any {
	t.Helper()
	objs, err := readYamlFile(doc)
	require.NoError(t, err)
	require.Len(t, objs, 1)
	containers, ok := objs[0].GetObject()["spec"].(map[string]any)["containers"].([]any)
	require.True(t, ok)
	require.Len(t, containers, 1)
	return containers[0].(map[string]any)
}

// A document that needs the YAML 1.1 reading must not lose the digits of an
// integer above 2^53. The boolean comes out as a bool only through that
// reading (yaml.v3 reads yes as a string), so asserting it proves the fallback
// ran.
func TestReadYamlFileYAML11FallbackKeepsLargeIntegersExact(t *testing.T) {
	for _, tt := range []struct {
		name  string
		value string
		want  any
	}{
		{"small", "1000", 1000},
		{"zero", "0", 0},
		{"2^53", "9007199254740992", 9007199254740992},
		{"2^53+1", "9007199254740993", 9007199254740993},
		{"max int64", "9223372036854775807", 9223372036854775807},
		{"negative above 2^53", "-9007199254740993", -9007199254740993},
		{"min int64", "-9223372036854775808", -9223372036854775808},
	} {
		t.Run(tt.name, func(t *testing.T) {
			sc := firstContainer(t, []byte(fmt.Sprintf(podBigInt, "yes", tt.value)))["securityContext"].(map[string]any)
			assert.Equal(t, true, sc["privileged"], "the YAML 1.1 reading did not run")
			assert.Equal(t, tt.want, sc["runAsUser"])
		})
	}
}

// Beyond what a manifest field can hold, the types are still the primary
// reading's and an integer never goes through float64.
func TestReparseAsYAML11NumberTypes(t *testing.T) {
	obj, ok := reparseAsYAML11([]byte(`a: 9223372036854775808
b: 18446744073709551615
c: 18446744073709551616
d: 1.5
e: [9007199254740993, {f: -9007199254740993}]
g: yes
`))
	require.True(t, ok)
	assert.Equal(t, uint64(9223372036854775808), obj["a"])
	assert.Equal(t, uint64(18446744073709551615), obj["b"])
	assert.Equal(t, float64(18446744073709551616), obj["c"])
	assert.Equal(t, 1.5, obj["d"])
	e := obj["e"].([]any)
	assert.Equal(t, 9007199254740993, e[0])
	assert.Equal(t, -9007199254740993, e[1].(map[string]any)["f"])
	assert.Equal(t, true, obj["g"])
}

// The numbers of a fallback document have the types the primary reading gives
// them, wherever they are nested.
func TestReadYamlFileYAML11FallbackConvertsNestedNumbers(t *testing.T) {
	doc := []byte(`apiVersion: v1
kind: Pod
metadata:
  name: p
  namespace: default
  labels:
    big: "9007199254740993"
spec:
  activeDeadlineSeconds: 9007199254740993
  terminationGracePeriodSeconds: 30
  containers:
    - name: app
      ports:
        - containerPort: 80
        - containerPort: 8080
      securityContext:
        privileged: yes
        allowPrivilegeEscalation: no
        runAsUser: 9007199254740993
        runAsGroup: -9007199254740993
`)
	objs, err := readYamlFile(doc)
	require.NoError(t, err)
	require.Len(t, objs, 1)
	spec := objs[0].GetObject()["spec"].(map[string]any)
	assert.Equal(t, 9007199254740993, spec["activeDeadlineSeconds"])
	assert.Equal(t, 30, spec["terminationGracePeriodSeconds"])
	c := spec["containers"].([]any)[0].(map[string]any)
	ports := c["ports"].([]any)
	assert.Equal(t, 80, ports[0].(map[string]any)["containerPort"])
	assert.Equal(t, 8080, ports[1].(map[string]any)["containerPort"])
	sc := c["securityContext"].(map[string]any)
	assert.Equal(t, true, sc["privileged"])
	assert.Equal(t, false, sc["allowPrivilegeEscalation"])
	assert.Equal(t, 9007199254740993, sc["runAsUser"])
	assert.Equal(t, -9007199254740993, sc["runAsGroup"])
	// A quoted number stays a string.
	assert.Equal(t, "9007199254740993", objs[0].GetObject()["metadata"].(map[string]any)["labels"].(map[string]any)["big"])
}

// The other YAML 1.1 booleans take the same route.
func TestReadYamlFileYAML11FallbackBooleansWithLargeIntegers(t *testing.T) {
	for _, w := range []struct {
		on, off string
	}{{"yes", "no"}, {"on", "off"}, {"Yes", "No"}} {
		doc := []byte(fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: p
  namespace: default
spec:
  containers:
    - name: app
      securityContext:
        privileged: %s
        allowPrivilegeEscalation: %s
        runAsUser: 9007199254740993
`, w.on, w.off))
		sc := firstContainer(t, doc)["securityContext"].(map[string]any)
		assert.Equal(t, true, sc["privileged"], w.on)
		assert.Equal(t, false, sc["allowPrivilegeEscalation"], w.off)
		assert.Equal(t, 9007199254740993, sc["runAsUser"], w.on)
	}
}

// A document that is valid without the YAML 1.1 reading is read as before: its
// integers are exact and its yes stays a string.
func TestReadYamlFileWithoutFallbackKeepsLargeIntegersExact(t *testing.T) {
	sc := firstContainer(t, []byte(fmt.Sprintf(podBigInt, "true", "9007199254740993")))["securityContext"].(map[string]any)
	assert.Equal(t, true, sc["privileged"])
	assert.Equal(t, 9007199254740993, sc["runAsUser"])
}

// The numbers reach the scan's JSON input unchanged.
func TestReadYamlFileYAML11FallbackMarshalsLargeIntegersExactly(t *testing.T) {
	objs, err := readYamlFile([]byte(fmt.Sprintf(podBigInt, "yes", "9007199254740993")))
	require.NoError(t, err)
	require.Len(t, objs, 1)
	out, err := json.Marshal(objs[0].GetObject())
	require.NoError(t, err)
	assert.Contains(t, string(out), `"runAsUser":9007199254740993`)
}
