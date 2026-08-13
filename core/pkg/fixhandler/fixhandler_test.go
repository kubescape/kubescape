package fixhandler

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	gitv5 "github.com/go-git/go-git/v5"
	"github.com/kubescape/go-logger"
	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v3/internal/testutils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/mikefarah/yq/v4/pkg/yqlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/op/go-logging.v1"
)

type indentationTestCase struct {
	inputFile      string
	yamlExpression string
	expectedFile   string
}

func NewFixHandlerMock() (*FixHandler, error) {
	backendLoggerLeveled := logging.AddModuleLevel(logging.NewLogBackend(logger.L().GetWriter(), "", 0))
	backendLoggerLeveled.SetLevel(logging.ERROR, "")
	yqlib.GetLogger().SetBackend(backendLoggerLeveled)

	return &FixHandler{
		fixInfo:       &metav1.FixInfo{},
		reportObj:     &reporthandlingv2.PostureReport{},
		localBasePath: "",
	}, nil
}

func getTestCases() []indentationTestCase {
	indentationTestCases := []indentationTestCase{
		// Insertion Scenarios
		{
			"inserts/tc-01-00-input-mapping-insert-mapping.yaml",
			"select(di==0).spec.containers[0].securityContext.allowPrivilegeEscalation |= false",
			"inserts/tc-01-01-expected.yaml",
		},
		{
			"inserts/tc-02-00-input-mapping-insert-mapping-with-list.yaml",
			"select(di==0).spec.containers[0].securityContext.capabilities.drop += [\"NET_RAW\"]",
			"inserts/tc-02-01-expected.yaml",
		},
		{
			"inserts/tc-03-00-input-list-append-scalar.yaml",
			"select(di==0).spec.containers[0].securityContext.capabilities.drop += [\"SYS_ADM\"]",
			"inserts/tc-03-01-expected.yaml",
		},
		{
			"inserts/tc-04-00-input-multiple-inserts.yaml",

			`select(di==0).spec.template.spec.securityContext.allowPrivilegeEscalation |= false |
			 select(di==0).spec.template.spec.containers[0].securityContext.capabilities.drop += ["NET_RAW"] |
			 select(di==0).spec.template.spec.containers[0].securityContext.seccompProfile.type |= "RuntimeDefault" |
			 select(di==0).spec.template.spec.containers[0].securityContext.allowPrivilegeEscalation |= false |
			 select(di==0).spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem |= true`,

			"inserts/tc-04-01-expected.yaml",
		},
		{
			"inserts/tc-05-00-input-comment-blank-line-single-insert.yaml",
			"select(di==0).spec.containers[0].securityContext.allowPrivilegeEscalation |= false",
			"inserts/tc-05-01-expected.yaml",
		},
		{
			"inserts/tc-06-00-input-list-append-scalar-oneline.yaml",
			"select(di==0).spec.containers[0].securityContext.capabilities.drop += [\"SYS_ADM\"]",
			"inserts/tc-06-01-expected.yaml",
		},
		{
			"inserts/tc-07-00-input-multiple-documents.yaml",

			`select(di==0).spec.containers[0].securityContext.allowPrivilegeEscalation |= false |
			 select(di==1).spec.containers[0].securityContext.allowPrivilegeEscalation |= false`,

			"inserts/tc-07-01-expected.yaml",
		},
		{
			"inserts/tc-08-00-input-mapping-insert-mapping-indented.yaml",
			"select(di==0).spec.containers[0].securityContext.capabilities.drop += [\"NET_RAW\"]",
			"inserts/tc-08-01-expected.yaml",
		},
		{
			"inserts/tc-09-00-input-list-insert-new-mapping-indented.yaml",
			`select(di==0).spec.containers += {"name": "redis", "image": "redis"}`,
			"inserts/tc-09-01-expected.yaml",
		},
		{
			"inserts/tc-10-00-input-list-insert-new-mapping.yaml",
			`select(di==0).spec.containers += {"name": "redis", "image": "redis"}`,
			"inserts/tc-10-01-expected.yaml",
		},
		{
			"inserts/tc-11-00-input-list-insert-new-mapping-crlf-newlines.yaml",
			`select(di==0).spec.containers += {"name": "redis", "image": "redis"}`,
			"inserts/tc-11-01-expected.yaml",
		},

		// Starts with ---
		{
			"inserts/tc-12-00-begin-with-document-separator.yaml",
			"select(di==0).spec.containers[0].securityContext.allowPrivilegeEscalation |= false",
			"inserts/tc-12-01-expected.yaml",
		},

		// Removal Scenarios
		{
			"removals/tc-01-00-input.yaml",
			"del(select(di==0).spec.containers[0].securityContext)",
			"removals/tc-01-01-expected.yaml",
		},
		{
			"removals/tc-02-00-input.yaml",
			"del(select(di==0).spec.containers[1])",
			"removals/tc-02-01-expected.yaml",
		},
		{
			"removals/tc-03-00-input.yaml",
			"del(select(di==0).spec.containers[0].securityContext.capabilities.drop[1])",
			"removals/tc-03-01-expected.yaml",
		},
		{
			"removals/tc-04-00-input.yaml",
			`del(select(di==0).spec.containers[0].securityContext) |
			 del(select(di==1).spec.containers[1])`,
			"removals/tc-04-01-expected.yaml",
		},

		// Replace Scenarios
		{
			"replaces/tc-01-00-input.yaml",
			"select(di==0).spec.containers[0].securityContext.runAsRoot |= false",
			"replaces/tc-01-01-expected.yaml",
		},
		{
			"replaces/tc-02-00-input.yaml",
			`select(di==0).spec.containers[0].securityContext.capabilities.drop[0] |= "SYS_ADM" |
			 select(di==0).spec.containers[0].securityContext.capabilities.add[0] |= "NET_RAW"`,
			"replaces/tc-02-01-expected.yaml",
		},

		// Hybrid Scenarios
		{
			"hybrids/tc-01-00-input.yaml",
			`del(select(di==0).spec.containers[0].securityContext) |
			 select(di==0).spec.securityContext.runAsRoot |= false`,
			"hybrids/tc-01-01-expected.yaml",
		},
		{
			"hybrids/tc-02-00-input-indented-list.yaml",
			`del(select(di==0).spec.containers[0].securityContext) |
			 select(di==0).spec.securityContext.runAsRoot |= false`,
			"hybrids/tc-02-01-expected.yaml",
		},
		{
			"hybrids/tc-03-00-input-comments.yaml",
			`del(select(di==0).spec.containers[0].securityContext) |
			 select(di==0).spec.securityContext.runAsRoot |= false`,
			"hybrids/tc-03-01-expected.yaml",
		},
		{
			"hybrids/tc-04-00-input-separated-keys.yaml",
			`del(select(di==0).spec.containers[0].securityContext) |
			 select(di==0).spec.securityContext.runAsRoot |= false`,
			"hybrids/tc-04-01-expected.yaml",
		},
		{
			"hybrids/tc-05-00-input-leading-doc-separator.yaml",
			`del(select(di==0).spec.containers[0].securityContext) |
			 select(di==0).spec.securityContext.runAsRoot |= false`,
			"hybrids/tc-05-01-expected.yaml",
		},
	}

	return indentationTestCases
}

func TestApplyFixKeepsFormatting(t *testing.T) {
	testCases := getTestCases()
	getTestDataPath := func(filename string) string {
		currentFile := "testdata/" + filename
		return filepath.Join(testutils.CurrentDir(), currentFile)
	}

	for _, tc := range testCases {
		t.Run(tc.inputFile, func(t *testing.T) {
			inputFilename := getTestDataPath(tc.inputFile)
			input, err := os.ReadFile(inputFilename)
			if err != nil {
				t.Fatalf(`Unable to open file %s due to: %v`, inputFilename, err)
			}
			expectedFilename := getTestDataPath(tc.expectedFile)
			wantRaw, err := os.ReadFile(expectedFilename)
			if err != nil {
				t.Fatalf(`Unable to open file %s due to: %v`, expectedFilename, err)
			}
			want := string(wantRaw)
			expression := tc.yamlExpression

			fileAsString := string(input)
			got, _ := ApplyFixToContent(context.Background(), fileAsString, expression)

			assert.Equalf(
				t, want, got,
				"Contents of the fixed file don't match the expectation.\n"+
					"Input file: %s\n\n"+
					"Got: <%s>\n\n"+
					"Want: <%s>",
				tc.inputFile, got, want,
			)
		},
		)

	}
}

// TestApplyFixToContent_EmptyLeadingDocument guards the regression from issue
// #2495: a file whose first document is empty (a comment followed by "---") is
// decoded inconsistently by go-yaml and yqlib, which used to make the fix
// renderer call logger.Fatal and os.Exit the whole process mid-write (leaving
// an empty SARIF file). It must now return an error gracefully instead.
func TestApplyFixToContent_EmptyLeadingDocument(t *testing.T) {
	yamlContent := "# a comment, followed by a document separator\n---\napiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: demo\nspec:\n  template:\n    spec:\n      containers:\n        - name: app\n          image: nginx:1.27\n"
	// The scanner counts the empty leading document, so the Deployment is di==1.
	expression := FixPathToValidYamlExpression("spec.template.spec.containers[0].image", "nginx:1.28", 1)

	got, err := ApplyFixToContent(context.Background(), yamlContent, expression)

	assert.Error(t, err, "expected a graceful error rather than a process exit")
	assert.Empty(t, got)
}

// TestApplyFixToContent_TopLevelFlowSequence covers a flow collection that is not nested
// under a key of its own, so it starts on the first line of the document. Resolving the
// line to replace picked the document node that shares that line and rendered it against
// its nil parent, panicking out of `kubescape fix` before anything was written. A nested
// flow sequence never hit this because the document node sits on an earlier line.
func TestApplyFixToContent_TopLevelFlowSequence(t *testing.T) {
	yamlContent := "args: [--foo]\n"
	expression := FixPathToValidYamlExpression("args[1]", "--bar", 0)

	got, err := ApplyFixToContent(context.Background(), yamlContent, expression)

	require.NoError(t, err)
	// the flow style of the original line is kept
	assert.Equal(t, "args: [--foo, --bar]\n", got)
}

func Test_fixPathToValidYamlExpression(t *testing.T) {
	type args struct {
		fixPath             string
		value               string
		documentIndexInYaml int
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "fix path with boolean value",
			args: args{
				fixPath:             "spec.template.spec.containers[0].securityContext.privileged",
				value:               "true",
				documentIndexInYaml: 2,
			},
			want: "select(di==2).spec.template.spec.containers[0].securityContext.privileged |= true",
		},
		{
			name: "fix path with string value",
			args: args{
				fixPath:             "metadata.namespace",
				value:               "YOUR_NAMESPACE",
				documentIndexInYaml: 0,
			},
			want: "select(di==0).metadata.namespace |= \"YOUR_NAMESPACE\"",
		},
		{
			name: "fix path with string containing quotes",
			args: args{
				fixPath:             "spec.template.spec.containers[0].command[1]",
				value:               "app=\"web\"",
				documentIndexInYaml: 0,
			},
			want: "select(di==0).spec.template.spec.containers[0].command[1] |= \"app=\\\"web\\\"\"",
		},
		{
			name: "fix path with string containing backslash",
			args: args{
				fixPath:             "path",
				value:               "C:\\path\\to",
				documentIndexInYaml: 0,
			},
			want: "select(di==0).path |= \"C:\\path\\to\"",
		},
		{
			name: "fix path with string containing newline",
			args: args{
				fixPath:             "path",
				value:               "line1\nline2",
				documentIndexInYaml: 0,
			},
			want: "select(di==0).path |= \"line1\nline2\"",
		},
		{
			name: "fix path with string containing tab",
			args: args{
				fixPath:             "path",
				value:               "a\tb",
				documentIndexInYaml: 0,
			},
			want: "select(di==0).path |= \"a\tb\"",
		},
		{
			name: "fix path with number",
			args: args{
				fixPath:             "xxx.yyy",
				value:               "123",
				documentIndexInYaml: 0,
			},
			want: "select(di==0).xxx.yyy |= 123",
		},
		{
			name: "fix path with NaN string value",
			args: args{
				fixPath:             "xxx.yyy",
				value:               "NaN",
				documentIndexInYaml: 0,
			},
			want: "select(di==0).xxx.yyy |= \"NaN\"",
		},
		{
			name: "fix path with Inf string value",
			args: args{
				fixPath:             "xxx.yyy",
				value:               "Inf",
				documentIndexInYaml: 0,
			},
			want: "select(di==0).xxx.yyy |= \"Inf\"",
		},
		{
			name: "fix path with -Inf string value",
			args: args{
				fixPath:             "xxx.yyy",
				value:               "-Inf",
				documentIndexInYaml: 0,
			},
			want: "select(di==0).xxx.yyy |= \"-Inf\"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FixPathToValidYamlExpression(tt.args.fixPath, tt.args.value, tt.args.documentIndexInYaml); got != tt.want {
				t.Errorf("fixPathToValidYamlExpression() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestJoinStrings(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "nil array",
			args: nil,
			want: "",
		},
		{
			name: "empty array",
			args: []string{},
			want: "",
		},
		{
			name: "single element",
			args: []string{"a"},
			want: "a",
		},
		{
			name: "two elements",
			args: []string{"a", "b"},
			want: "ab",
		},
		{
			name: "three elements",
			args: []string{"a", "b", "c"},
			want: "abc",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := joinStrings(tt.args...); got != tt.want {
				t.Errorf("joinStrings() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetFileString(t *testing.T) {
	type args struct {
		filePath string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "file not found",
			args: args{
				filePath: "notfound.yaml",
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "file found",
			args: args{
				filePath: filepath.Join("testdata", "inserts", "tc-01-00-input-mapping-insert-mapping.yaml"),
			},
			want: `# Fix to Apply:
# "select(di==0).spec.containers[0].securityContext.allowPrivilegeEscalation |= false"

apiVersion: v1
kind: Pod
metadata:
  name: insert_to_mapping_node_1

spec:
  containers:
  - name: nginx_container
    image: nginx
`,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if runtime.GOOS == "windows" {
				return
			}
			got, err := GetFileString(tt.args.filePath)
			if (err != nil) != tt.wantErr {
				t.Errorf("getFileString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want && !tt.wantErr {
				t.Errorf("getFileString() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDetermineNewlineSeparator(t *testing.T) {
	type args struct {
		fileString string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "empty",
			args: args{
				fileString: "",
			},
			want: "\n",
		},
		{
			name: "windows newline",
			args: args{
				fileString: "a\r\nb\r\nc\r\n",
			},
			want: "\r\n",
		},
		{
			name: "linux newline",
			args: args{
				fileString: "a\nb\nc\n",
			},
			want: "\n",
		},
		{
			name: "oldmac newline",
			args: args{
				fileString: "a\rb\rc\r",
			},
			want: "\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := determineNewlineSeparator(tt.args.fileString); got != tt.want {
				t.Errorf("determineNewlineSeparator() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSanitizeYaml(t *testing.T) {
	type args struct {
		fileString string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "empty yaml",
			args: args{
				fileString: "",
			},
			want: "",
		},
		{
			name: "empty yaml with two characters",
			args: args{
				fileString: "##",
			},
			want: "##",
		},
		{
			name: "yaml/v3",
			args: args{
				fileString: `apiVersion: v1
kind: Pod
metadata:
  name: insert_to_mapping_node_1
`,
			},
			want: `apiVersion: v1
kind: Pod
metadata:
  name: insert_to_mapping_node_1
`,
		},
		{
			name: "yaml/v2",
			args: args{
				fileString: `apiVersion: v1
kind: Pod
metadata:
  name: insert_to_mapping_node_1
---
apiVersion: v1
kind: Pod
metadata:
  name: insert_to_mapping_node_2
`,
			},
			want: `apiVersion: v1
kind: Pod
metadata:
  name: insert_to_mapping_node_1
---
apiVersion: v1
kind: Pod
metadata:
  name: insert_to_mapping_node_2
`,
		},
		{
			name: "yaml/v1",
			args: args{
				fileString: `---
apiVersion: v1
kind: Pod
metadata:
  name: insert_to_mapping_node_1
`,
			},
			want: `# ---
apiVersion: v1
kind: Pod
metadata:
  name: insert_to_mapping_node_1
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeYaml(tt.args.fileString); got != tt.want {
				t.Errorf("sanitizeYaml() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestRevertSanitizeYaml guards the `< 5` / `[:5]` pairing: the guard was
// previously `< 3` while the slice was `[:5]`, so any 3-4 byte input panicked
// with "slice bounds out of range". Covers every length from 0 up to and past
// the "# ---" marker, since that boundary is exactly where the bug lived.
func TestRevertSanitizeYaml(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "length 0", in: "", want: ""},
		{name: "length 1", in: "-", want: "-"},
		{name: "length 2", in: "--", want: "--"},
		{name: "length 3 (previously panicked)", in: "# -", want: "# -"},
		{name: "length 4 (previously panicked)", in: "# --", want: "# --"},
		{name: "length 5, marker present", in: "# ---", want: "---"},
		{name: "length 5, marker absent", in: "# abc", want: "# abc"},
		{name: "marker with trailing content", in: "# ---\nkind: Pod\n", want: "---\nkind: Pod\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotPanics(t, func() {
				got := revertSanitizeYaml(tt.in)
				assert.Equal(t, tt.want, got)
			})
		})
	}
}

// TestSanitizeYaml_RoundTrip confirms revertSanitizeYaml undoes sanitizeYaml
// for the case both were built for: a document starting with "---".
func TestSanitizeYaml_RoundTrip(t *testing.T) {
	original := "---\napiVersion: v1\nkind: Pod\n"
	sanitized := sanitizeYaml(original)
	assert.Equal(t, "# ---\napiVersion: v1\nkind: Pod\n", sanitized)
	assert.Equal(t, original, revertSanitizeYaml(sanitized))
}

func TestReduceYamlExpressions(t *testing.T) {
	type args struct {
		yamlExpressions []string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "empty",
			args: args{
				yamlExpressions: []string{},
			},
			want: "",
		},
		{
			name: "one expression",
			args: args{
				yamlExpressions: []string{
					"select(di==0).spec.containers[0].securityContext.allowPrivilegeEscalation |= false",
				},
			},
			want: "select(di==0).spec.containers[0].securityContext.allowPrivilegeEscalation |= false",
		},
		{
			name: "two expressions",
			args: args{
				yamlExpressions: []string{
					"select(di==0).spec.containers[0].securityContext.allowPrivilegeEscalation |= false",
					"select(di==0).spec.containers[0].securityContext.capabilities.drop += [\"NET_RAW\"]",
				},
			},
			want: "select(di==0).spec.containers[0].securityContext.allowPrivilegeEscalation |= false | select(di==0).spec.containers[0].securityContext.capabilities.drop += [\"NET_RAW\"]",
		},
		{
			name: "Duplicate expressions",
			args: args{
				yamlExpressions: []string{
					"select(di==0).spec.containers[0].securityContext.allowPrivilegeEscalation |= false",
					"select(di==0).spec.containers[0].securityContext.capabilities.drop += [\"NET_RAW\"]",
					"select(di==0).spec.containers[0].securityContext.allowPrivilegeEscalation |= false",
				},
			},
			want: "select(di==0).spec.containers[0].securityContext.allowPrivilegeEscalation |= false | select(di==0).spec.containers[0].securityContext.capabilities.drop += [\"NET_RAW\"]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resource := &ResourceFixInfo{}
			resource.YamlExpressions = make(map[string]armotypes.FixPath)

			for _, yamlExpression := range tt.args.yamlExpressions {
				resource.YamlExpressions[yamlExpression] = armotypes.FixPath{}
			}
			got := reduceYamlExpressions(resource)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetLocalPath(t *testing.T) {
	type args struct {
		report *reporthandlingv2.PostureReport
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "empty report",
			args: args{
				report: &reporthandlingv2.PostureReport{},
			},
			want: "",
		},
		{
			name: "No scan metadata",
			args: args{
				report: &reporthandlingv2.PostureReport{
					Metadata: reporthandlingv2.Metadata{
						ScanMetadata: reporthandlingv2.ScanMetadata{},
					},
				},
			},
			want: "",
		},
		{
			name: "Scan target GitLocal",
			args: args{
				report: &reporthandlingv2.PostureReport{
					Metadata: reporthandlingv2.Metadata{
						ScanMetadata: reporthandlingv2.ScanMetadata{
							ScanningTarget: reporthandlingv2.ScanningTarget(3),
						},
						ContextMetadata: reporthandlingv2.ContextMetadata{
							RepoContextMetadata: &reporthandlingv2.RepoContextMetadata{
								LocalRootPath: os.TempDir(),
							},
						},
					},
				},
			},
			want: os.TempDir(),
		},
		{
			name: "Scan target GitLocal without repository metadata",
			args: args{
				report: &reporthandlingv2.PostureReport{
					Metadata: reporthandlingv2.Metadata{
						ScanMetadata: reporthandlingv2.ScanMetadata{
							ScanningTarget: reporthandlingv2.GitLocal,
						},
					},
				},
			},
			want: "",
		},
		{
			name: "nil report",
			args: args{
				report: nil,
			},
			want: "",
		},
		{
			name: "Scan target Directory",
			args: args{
				report: &reporthandlingv2.PostureReport{
					Metadata: reporthandlingv2.Metadata{
						ScanMetadata: reporthandlingv2.ScanMetadata{
							ScanningTarget: reporthandlingv2.ScanningTarget(2),
						},
						ContextMetadata: reporthandlingv2.ContextMetadata{
							DirectoryContextMetadata: &reporthandlingv2.DirectoryContextMetadata{
								BasePath: os.TempDir(),
							},
						},
					},
				},
			},
		},
		{
			name: "Scan target File",
			args: args{
				report: &reporthandlingv2.PostureReport{
					Metadata: reporthandlingv2.Metadata{
						ScanMetadata: reporthandlingv2.ScanMetadata{
							ScanningTarget: reporthandlingv2.ScanningTarget(1),
						},
						ContextMetadata: reporthandlingv2.ContextMetadata{
							FileContextMetadata: &reporthandlingv2.FileContextMetadata{
								FilePath: filepath.Join(os.TempDir(), "target.yaml"),
							},
						},
					},
				},
			},
			want: filepath.Dir(filepath.Join(os.TempDir(), "target.yaml")),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getLocalPath(tt.args.report); got != tt.want {
				t.Errorf("getLocalPath() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestPrepareHelmSuggestions_RoutesHelmAwayFromYqAndCarriesValuesPaths
// verifies the partition that issue #1772 hinges on: a Helm-rendered
// resource must (a) be excluded from the yq-based ResourceFixInfo path
// — applying yq edits using rendered-YAML line numbers is the original bug
// — and (b) surface as a HelmFixSuggestion carrying the .Values keys
// statically traced from the source template, so the user can edit
// values.yaml deliberately.
func TestPrepareHelmSuggestions_RoutesHelmAwayFromYqAndCarriesValuesPaths(t *testing.T) {
	failed := apis.StatusInfo{InnerStatus: apis.StatusFailed}

	// Helm-source resource: must end up in HelmFixSuggestion, never in ResourceFixInfo.
	helmObj := map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": "api"},
	}
	helmRes := &reporthandling.Resource{
		Object: helmObj,
		Source: &reporthandling.Source{
			FileType:         reporthandling.SourceTypeHelmChart,
			HelmPath:         "/charts/myapp",
			HelmChartName:    "myapp",
			HelmTemplateFile: "templates/deployment.yaml",
			HelmValuesPaths:  []string{"image.tag", "replicaCount"},
		},
	}
	// Resource ID is derived by the IMetadata middleware from Object, not
	// from the ResourceID field — populate it via GetID() so buildResourcesMap
	// keys match the result lookup.
	resID := helmRes.GetID()

	report := &reporthandlingv2.PostureReport{
		Resources: []reporthandling.Resource{*helmRes},
		Results: []resourcesresults.Result{{
			ResourceID:  resID,
			RawResource: helmRes,
			AssociatedControls: []resourcesresults.ResourceAssociatedControl{{
				ControlID: "C-0001",
				Status:    failed,
				ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{{
					Name:   "rule-x",
					Status: apis.StatusFailed,
					Paths: []armotypes.PosturePaths{{
						FixPath: armotypes.FixPath{
							Path:  "spec.template.spec.containers[0].securityContext.runAsNonRoot",
							Value: "true",
						},
					}},
				}},
			}},
		}},
	}

	h, err := NewFixHandlerMock()
	assert.NoError(t, err)
	h.reportObj = report

	rfi := h.PrepareResourcesToFix(context.TODO())
	assert.Len(t, rfi, 0, "Helm-rendered resources must not enter the yq-based fix path")

	suggestions := h.PrepareHelmSuggestions(context.TODO())
	assert.Len(t, suggestions, 1)
	s := suggestions[0]
	assert.Equal(t, "myapp", s.ChartName)
	assert.Equal(t, "/charts/myapp", s.ChartPath)
	assert.Equal(t, "templates/deployment.yaml", s.TemplateFile)
	assert.Equal(t, []string{"image.tag", "replicaCount"}, s.ValuesPaths)
	assert.Len(t, s.FixPaths, 1)
	assert.Equal(t, "true", s.FixPaths[0].Value)
}

// TestPrepareHelmSuggestions_MixedHelmAndYamlResources verifies the partition
// holds when a single report contains both a Helm-rendered resource and a
// plain YAML resource: the YAML one must take the yq-based ResourceFixInfo
// path, the Helm one must take the HelmFixSuggestion path, and neither should
// leak into the other. This is the case that issue #1772 actually surfaces
// in practice — users scan directories that mix Helm charts with raw manifests.
func TestPrepareHelmSuggestions_MixedHelmAndYamlResources(t *testing.T) {
	failed := apis.StatusInfo{InnerStatus: apis.StatusFailed}

	// Plain YAML resource: needs a real file on disk because
	// PrepareResourcesToFix stat()s the resolved path before queuing it.
	tmpDir := t.TempDir()
	yamlRelPath := "deploy.yaml"
	yamlContent := "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n"
	if err := os.WriteFile(filepath.Join(tmpDir, yamlRelPath), []byte(yamlContent), 0600); err != nil {
		t.Fatalf("write yaml fixture: %v", err)
	}

	yamlObj := map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": "web"},
		// sourcePath flags this as a LocalWorkload and feeds getFilePathAndIndex.
		"sourcePath": yamlRelPath + ":0",
	}
	yamlRes := &reporthandling.Resource{
		Object: yamlObj,
		Source: &reporthandling.Source{FileType: reporthandling.SourceTypeYaml},
	}
	yamlResID := yamlRes.GetID()

	helmObj := map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": "api"},
	}
	helmRes := &reporthandling.Resource{
		Object: helmObj,
		Source: &reporthandling.Source{
			FileType:         reporthandling.SourceTypeHelmChart,
			HelmPath:         "/charts/myapp",
			HelmChartName:    "myapp",
			HelmTemplateFile: "templates/deployment.yaml",
			HelmValuesPaths:  []string{"image.tag"},
		},
	}
	helmResID := helmRes.GetID()

	mkResult := func(rid string, raw *reporthandling.Resource, fixPath string) resourcesresults.Result {
		return resourcesresults.Result{
			ResourceID:  rid,
			RawResource: raw,
			AssociatedControls: []resourcesresults.ResourceAssociatedControl{{
				ControlID: "C-0001",
				Status:    failed,
				ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{{
					Name:   "rule-x",
					Status: apis.StatusFailed,
					Paths: []armotypes.PosturePaths{{
						FixPath: armotypes.FixPath{Path: fixPath, Value: "true"},
					}},
				}},
			}},
		}
	}

	report := &reporthandlingv2.PostureReport{
		Resources: []reporthandling.Resource{*yamlRes, *helmRes},
		Results: []resourcesresults.Result{
			mkResult(yamlResID, yamlRes, "spec.template.spec.containers[0].securityContext.runAsNonRoot"),
			mkResult(helmResID, helmRes, "spec.template.spec.containers[0].securityContext.runAsNonRoot"),
		},
	}

	h, err := NewFixHandlerMock()
	assert.NoError(t, err)
	h.reportObj = report
	h.localBasePath = tmpDir

	rfi := h.PrepareResourcesToFix(context.TODO())
	assert.Len(t, rfi, 1, "exactly the plain YAML resource should reach the yq-based fix path")
	assert.Equal(t, filepath.Join(tmpDir, yamlRelPath), rfi[0].FilePath)
	assert.Equal(t, yamlResID, rfi[0].Resource.GetID(), "ResourceFixInfo must not contain the Helm-rendered resource")

	suggestions := h.PrepareHelmSuggestions(context.TODO())
	assert.Len(t, suggestions, 1, "exactly the Helm resource should produce a HelmFixSuggestion")
	assert.Equal(t, "myapp", suggestions[0].ChartName)
	assert.Equal(t, []string{"image.tag"}, suggestions[0].ValuesPaths)
}

func TestGetFilePathAndIndex(t *testing.T) {
	h := &FixHandler{}

	tests := []struct {
		name          string
		input         string
		expectedPath  string
		expectedIndex int
		expectErr     bool
	}{
		{
			name:          "windows absolute path",
			input:         "C:\\Users\\admin\\deploy.yaml:2",
			expectedPath:  "C:\\Users\\admin\\deploy.yaml",
			expectedIndex: 2,
			expectErr:     false,
		},
		{
			name:          "unix path containing colon",
			input:         "dir:with:colon/deploy.yaml:3",
			expectedPath:  "dir:with:colon/deploy.yaml",
			expectedIndex: 3,
			expectErr:     false,
		},
		{
			name:          "standard unix path",
			input:         "/tmp/deploy.yaml:1",
			expectedPath:  "/tmp/deploy.yaml",
			expectedIndex: 1,
			expectErr:     false,
		},
		{
			name:      "missing separator",
			input:     "deploy.yaml",
			expectErr: true,
		},
		{
			name:      "invalid document index",
			input:     "deploy.yaml:not-a-number",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, index, err := h.getFilePathAndIndex(tt.input)

			if tt.expectErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.expectedPath, path)
			require.Equal(t, tt.expectedIndex, index)
		})
	}
}

func TestNewFixHandler_WrongJSON(t *testing.T) {
	// Regression test: arbitrary JSON must return invalidReportFileErr, not unsupported-target error
	reportJSON := `{"key":"value"}`
	tmpFile, err := os.CreateTemp("", "report-*.json")
	assert.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	_, err = tmpFile.WriteString(reportJSON)
	assert.NoError(t, err)
	tmpFile.Close()

	fixInfo := &metav1.FixInfo{ReportFile: tmpFile.Name()}
	_, err = NewFixHandler(fixInfo)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid report file: not a valid kubescape scan report. Please provide a JSON file generated by 'kubescape scan --format json'")
}

func TestNewFixHandler_MalformedReportishJSON(t *testing.T) {
	// Regression test: JSON that looks report-ish but lacks real scanMetadata must return invalidReportFileErr
	for _, reportJSON := range []string{
		`{"metadata":{"foo":"bar"},"results":[]}`,
		`{"metadata":{"scanMetadata":{}},"results":[]}`,
	} {
		tmpFile, err := os.CreateTemp("", "report-*.json")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())
		_, err = tmpFile.WriteString(reportJSON)
		require.NoError(t, err)
		tmpFile.Close()

		fixInfo := &metav1.FixInfo{ReportFile: tmpFile.Name()}
		_, err = NewFixHandler(fixInfo)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid report file: not a valid kubescape scan report. Please provide a JSON file generated by 'kubescape scan --format json'")
	}
}

func TestNewFixHandler_ClusterReportUnsupportedTarget(t *testing.T) {
	// Regression test: cluster reports must surface "unsupported scanning target"
	const unsupported = "unsupported scanning target"
	const invalid = "invalid report file: not a valid kubescape scan report. Please provide a JSON file generated by 'kubescape scan --format json'"
	for name, reportJSON := range map[string]string{
		"explicit-0-minimal":          `{"metadata":{"scanMetadata":{"scanningTarget":0}},"generationTime":"2024-01-01T00:00:00Z","results":[]}`,
		"explicit-0-with-cluster-ctx": `{"metadata":{"scanMetadata":{"scanningTarget":0},"targetMetadata":{"clusterContextMetadata":{"contextName":"dev"}}},"generationTime":"2024-01-01T00:00:00Z","results":[]}`,
		"omitempty-absent-target":     `{"metadata":{"scanMetadata":{"targetType":"cluster"}},"generationTime":"2024-01-01T00:00:00Z","results":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			tmpFile, err := os.CreateTemp("", "report-*.json")
			require.NoError(t, err)
			defer os.Remove(tmpFile.Name())
			_, err = tmpFile.WriteString(reportJSON)
			require.NoError(t, err)
			tmpFile.Close()

			fixInfo := &metav1.FixInfo{ReportFile: tmpFile.Name()}
			_, err = NewFixHandler(fixInfo)
			require.Error(t, err)
			assert.Contains(t, err.Error(), unsupported)
			assert.NotContains(t, err.Error(), invalid)
		})
	}
}

func TestNewFixHandler_ClusterReportRoundTrip(t *testing.T) {
	// Regression test for the round-trip case: a cluster report marshaled from
	// reporthandlingv2 types. Cluster is the zero enum value (0) and scanningTarget
	// is tagged omitempty, so scanMetadata serializes as {} with no scanningTarget
	// key. Such a report must surface "unsupported scanning target", not
	// "invalid report file" — it is recognized by its clusterContextMetadata.
	var report reporthandlingv2.PostureReport
	report.Metadata.ScanMetadata.ScanningTarget = reporthandlingv2.Cluster
	report.Metadata.ContextMetadata.ClusterContextMetadata = &reporthandlingv2.ClusterMetadata{ContextName: "dev"}

	reportJSON, err := json.Marshal(report)
	require.NoError(t, err)
	// sanity-check the round-trip really dropped scanningTarget
	require.Contains(t, string(reportJSON), `"scanMetadata":{}`)

	tmpFile, err := os.CreateTemp("", "report-*.json")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	_, err = tmpFile.Write(reportJSON)
	require.NoError(t, err)
	tmpFile.Close()

	_, err = NewFixHandler(&metav1.FixInfo{ReportFile: tmpFile.Name()})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported scanning target")
	assert.NotContains(t, err.Error(), "invalid report file")
}

func TestNewFixHandler_EmptyReportGUID(t *testing.T) {
	// Regression test: a valid local scan report may have an empty reportGUID
	// (PostureReportWithSeverity does not serialize reportGUID).
	// NewFixHandler must not reject such reports based on ReportID alone.
	reportJSON := `{"metadata":{"scanMetadata":{"scanningTarget":4},"targetMetadata":{"directoryContextMetadata":{"basePath":"testdata"}}},"generationTime":"2024-01-01T00:00:00Z"}`
	tmpFile, err := os.CreateTemp("", "report-*.json")
	assert.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	_, err = tmpFile.WriteString(reportJSON)
	assert.NoError(t, err)
	tmpFile.Close()

	fixInfo := &metav1.FixInfo{ReportFile: tmpFile.Name()}
	_, err = NewFixHandler(fixInfo)
	// Should NOT fail with "invalid report file" — may fail on localPath stat, but not on empty ReportID
	if err != nil {
		assert.NotContains(t, err.Error(), "invalid report file: not a valid kubescape scan report. Please provide a JSON file generated by 'kubescape scan --format json'")
	}
}

// TestResourceBasePath covers the shapes the report-wide path gets wrong. In both of
// them the resource's own root is an ancestor of the report-wide path rather than a
// descendant, so it must be honoured, not rejected: a single-file scan records the file
// instead of its root, and a multi-input scan records only the first input.
func TestResourceBasePath(t *testing.T) {
	base := t.TempDir()
	ancestor := filepath.Dir(base)
	unrelated := t.TempDir()

	tests := []struct {
		name   string
		source *reporthandling.Source
		want   string
	}{
		{name: "no source at all falls back", source: nil, want: base},
		{name: "empty source path falls back", source: &reporthandling.Source{}, want: base},
		{name: "the report-wide root itself", source: &reporthandling.Source{Path: base}, want: base},
		{name: "an ancestor is honoured, as in a single-file scan", source: &reporthandling.Source{Path: ancestor}, want: ancestor},
		{name: "an unrelated root is honoured, as in a multi-input scan", source: &reporthandling.Source{Path: unrelated}, want: unrelated},
		{name: "a relative root falls back rather than resolving against the cwd", source: &reporthandling.Source{Path: "relative/dir"}, want: base},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &FixHandler{localBasePath: base, fixInfo: &metav1.FixInfo{}}
			assert.Equal(t, tt.want, h.resourceBasePath(&reporthandling.Resource{Source: tt.source}))
		})
	}
}

// TestResourceBasePath_ConstrainedByBasePath covers --base-path, the anchor the caller
// vouches for rather than one the report supplies. Source.Path is report input like any
// other, so it must be held to that anchor too; without this it would be the one way a
// report could still name a fix root outside it.
func TestResourceBasePath_ConstrainedByBasePath(t *testing.T) {
	trusted, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	inside := filepath.Join(trusted, "repo")
	require.NoError(t, os.MkdirAll(inside, 0o750))

	outside, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)

	tests := []struct {
		name       string
		basePath   string
		sourcePath string
		want       string
	}{
		{name: "inside the trusted anchor is honoured", basePath: trusted, sourcePath: inside, want: inside},
		{name: "the anchor itself is honoured", basePath: trusted, sourcePath: trusted, want: trusted},
		{name: "outside the trusted anchor falls back", basePath: trusted, sourcePath: outside, want: inside},
		{name: "without an anchor any absolute root is honoured", basePath: "", sourcePath: outside, want: outside},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &FixHandler{
				localBasePath: inside,
				fixInfo:       &metav1.FixInfo{BasePath: tt.basePath},
			}
			resource := &reporthandling.Resource{Source: &reporthandling.Source{Path: tt.sourcePath}}
			assert.Equal(t, tt.want, h.resourceBasePath(resource))
		})
	}
}

// TestPrepareResourcesToFix_SingleFileScanInsideRepository is the regression test for a
// single-file scan of a manifest inside a repository whose git metadata is unusable. The
// loader anchors on the repository root, so the report's relative path carries the
// manifest's full path from that root while the File target records only the file. If
// `fix` derives a different anchor than the scan did, the join doubles the intermediate
// directories and every control comes back as "file not found".
func TestPrepareResourcesToFix_SingleFileScanInsideRepository(t *testing.T) {
	repoRoot, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	_, err = gitv5.PlainInit(repoRoot, false)
	require.NoError(t, err)

	relPath := filepath.Join("workloads", "apps", "base", "app", "cronjobs.yaml")
	absPath := filepath.Join(repoRoot, relPath)
	require.NoError(t, os.MkdirAll(filepath.Dir(absPath), 0o750))
	require.NoError(t, os.WriteFile(absPath, []byte("apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n"), 0o600))

	report := singleResourceReport(t, repoRoot, filepath.ToSlash(relPath))
	report.Metadata.ScanMetadata.ScanningTarget = reporthandlingv2.File
	report.Metadata.ContextMetadata.FileContextMetadata = &reporthandlingv2.FileContextMetadata{FilePath: absPath}

	h, err := NewFixHandlerMock()
	require.NoError(t, err)
	h.reportObj = report
	// what NewFixHandler would derive for this report
	h.localBasePath = getLocalPath(report)

	rfi := h.PrepareResourcesToFix(context.TODO())
	require.Len(t, rfi, 1, "the manifest must resolve; unfixed: %+v", h.unfixedControls)
	assert.Equal(t, absPath, rfi[0].FilePath)
}

// TestPrepareResourcesToFix_RejectsTraversingRelativePath pins the traversal defence on
// the field that can actually carry "..": the relative path recorded for the resource.
func TestPrepareResourcesToFix_RejectsTraversingRelativePath(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)

	outside := filepath.Join(filepath.Dir(base), "outside.yaml")
	require.NoError(t, os.WriteFile(outside, []byte("apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n"), 0o600))
	t.Cleanup(func() { _ = os.Remove(outside) })

	report := singleResourceReport(t, base, "../"+filepath.Base(outside))

	h, err := NewFixHandlerMock()
	require.NoError(t, err)
	h.reportObj = report
	h.localBasePath = base

	rfi := h.PrepareResourcesToFix(context.TODO())
	assert.Empty(t, rfi, "a resource path escaping its root must not be queued for a write")
	require.Len(t, h.unfixedControls, 1)
	assert.Equal(t, "skipped: resource path escapes scanned directory", h.unfixedControls[0].Reason)
}

// singleResourceReport builds a report with one failed YAML resource rooted at
// sourcePath and recorded at relPath.
func singleResourceReport(t *testing.T, sourcePath, relPath string) *reporthandlingv2.PostureReport {
	t.Helper()

	resource := &reporthandling.Resource{
		Object: map[string]any{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata":   map[string]any{"name": "p"},
			"sourcePath": relPath + ":0",
		},
		Source: &reporthandling.Source{FileType: reporthandling.SourceTypeYaml, Path: sourcePath, RelativePath: relPath},
	}

	return &reporthandlingv2.PostureReport{
		Resources: []reporthandling.Resource{*resource},
		Results: []resourcesresults.Result{{
			ResourceID:  resource.GetID(),
			RawResource: resource,
			AssociatedControls: []resourcesresults.ResourceAssociatedControl{{
				ControlID: "C-0001",
				Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
				ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{{
					Name:   "rule-x",
					Status: apis.StatusFailed,
					Paths: []armotypes.PosturePaths{{
						FixPath: armotypes.FixPath{Path: "spec.containers[0].securityContext.runAsNonRoot", Value: "true"},
					}},
				}},
			}},
		}},
	}
}
