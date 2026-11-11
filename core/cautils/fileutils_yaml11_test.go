package cautils

import (
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
