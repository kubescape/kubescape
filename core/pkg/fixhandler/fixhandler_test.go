package fixhandler

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	logger "github.com/kubescape/go-logger"
	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v3/internal/testutils"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/mikefarah/yq/v4/pkg/yqlib"
	"github.com/stretchr/testify/assert"
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
			got, _ := ApplyFixToContent(context.TODO(), fileAsString, expression)

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
			name: "fix path with number",
			args: args{
				fixPath:             "xxx.yyy",
				value:               "123",
				documentIndexInYaml: 0,
			},
			want: "select(di==0).xxx.yyy |= 123",
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
