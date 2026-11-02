package pss

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sourcePod returns a Pod manifest named name, for building multi-document
// files whose line numbers the tests below count.
func sourcePod(name string) string {
	return `apiVersion: v1
kind: Pod
metadata:
  name: ` + name + `
spec:
  containers:
  - name: app
    image: nginx
`
}

func TestParseLocalWorkloadSources_Positions(t *testing.T) {
	jsonPod := func(name string) string {
		return `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"` + name + `"},"spec":{"containers":[{"name":"app","image":"nginx"}]}}`
	}

	for _, tc := range []struct {
		name    string
		file    string
		content string
		// want is each workload's line and column, in file order.
		want [][2]int
	}{
		{
			name:    "single document",
			file:    "pod.yaml",
			content: sourcePod("a"),
			want:    [][2]int{{1, 1}},
		},
		{
			name: "documents after separators, comments and blank lines",
			file: "pods.yaml",
			content: "# leading comment\n\n---\n" + sourcePod("a") +
				"---\n" + sourcePod("b") +
				"--- # separator with a comment\n\n# comment\n" + sourcePod("c"),
			want: [][2]int{{4, 1}, {13, 1}, {24, 1}},
		},
		{
			name:    "workload after a skipped kind",
			file:    "mixed.yaml",
			content: "apiVersion: v1\nkind: Service\nmetadata:\n  name: svc\n---\n" + sourcePod("a"),
			want:    [][2]int{{6, 1}},
		},
		{
			name:    "indented document",
			file:    "indented.yaml",
			content: "---\n  apiVersion: v1\n  kind: Pod\n  metadata:\n    name: a\n  spec:\n    containers:\n    - name: app\n      image: nginx\n",
			want:    [][2]int{{2, 3}},
		},
		{
			name:    "CRLF line endings",
			file:    "crlf.yaml",
			content: strings.ReplaceAll(sourcePod("a")+"---\n"+sourcePod("b"), "\n", "\r\n"),
			want:    [][2]int{{1, 1}, {10, 1}},
		},
		{
			name:    "JSON records on separate lines",
			file:    "pods.json",
			content: jsonPod("a") + "\n\n" + jsonPod("b") + "\n",
			want:    [][2]int{{1, 1}, {3, 1}},
		},
		{
			name:    "JSON records on one line",
			file:    "stream.json",
			content: "  " + jsonPod("a") + " " + jsonPod("b"),
			want:    [][2]int{{1, 3}, {1, 4 + len(jsonPod("a"))}},
		},
		{
			name:    "identical JSON records",
			file:    "same.json",
			content: jsonPod("a") + "\n" + jsonPod("a") + "\n",
			want:    [][2]int{{1, 1}, {2, 1}},
		},
		{
			name: "List items are located at the List",
			file: "list.yaml",
			content: sourcePod("a") + "---\n# a list\napiVersion: v1\nkind: List\nitems:\n" +
				"- " + strings.ReplaceAll(strings.TrimSuffix(sourcePod("b"), "\n"), "\n", "\n  ") + "\n" +
				"- " + strings.ReplaceAll(strings.TrimSuffix(sourcePod("c"), "\n"), "\n", "\n  ") + "\n",
			want: [][2]int{{1, 1}, {11, 1}, {11, 1}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), tc.file)
			require.NoError(t, os.WriteFile(path, []byte(tc.content), 0600))

			workloads, err := ParseLocalWorkloadSources([]string{path})
			require.NoError(t, err)

			got := make([][2]int, 0, len(workloads))
			for _, w := range workloads {
				require.NotNil(t, w.Source, w.GetName())
				assert.Equal(t, path, w.Source.File)
				got = append(got, [2]int{w.Source.Line, w.Source.Column})
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestParseLocalWorkloadSources_Directory(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(sourcePod("a")), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "b.yml"), []byte("---\n"+sourcePod("b")), 0600))

	workloads, err := ParseLocalWorkloadSources([]string{dir})
	require.NoError(t, err)
	require.Len(t, workloads, 2)
	assert.Equal(t, &Source{File: filepath.Join(dir, "a.yaml"), Line: 1, Column: 1}, workloads[0].Source)
	assert.Equal(t, &Source{File: filepath.Join(dir, "b.yml"), Line: 2, Column: 1}, workloads[1].Source)
}

func TestParseLocalWorkloadSourcesFromReader_NoSource(t *testing.T) {
	workloads, err := ParseLocalWorkloadSourcesFromReader(strings.NewReader(sourcePod("a")), "stdin")
	require.NoError(t, err)
	require.Len(t, workloads, 1)
	assert.Equal(t, "a", workloads[0].GetName())
	assert.Nil(t, workloads[0].Source)
}

func TestAggregateLocal_CarriesSource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pods.yaml")
	privileged := strings.Replace(sourcePod("bad"), "    image: nginx\n",
		"    image: nginx\n    securityContext:\n      privileged: true\n", 1)
	require.NoError(t, os.WriteFile(path, []byte(sourcePod("good")+"---\n"+privileged), 0600))

	workloads, err := ParseLocalWorkloadSources([]string{path})
	require.NoError(t, err)

	result := AggregateLocal("", workloads, Baseline)
	require.Len(t, result.Results, 2)
	sources := map[string]*Source{}
	for _, r := range result.Results {
		sources[r.Name] = r.Source
	}
	assert.Equal(t, &Source{File: path, Line: 1, Column: 1}, sources["good"])
	assert.Equal(t, &Source{File: path, Line: 10, Column: 1}, sources["bad"])

	// Aggregate has no sources to carry.
	for _, r := range Aggregate("", localWorkloadObjects(workloads), Baseline).Results {
		assert.Nil(t, r.Source, r.Name)
	}
}
