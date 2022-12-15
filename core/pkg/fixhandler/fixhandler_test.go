package fixhandler

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	logger "github.com/kubescape/go-logger"
	metav1 "github.com/kubescape/kubescape/v2/core/meta/datastructures/v1"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/mikefarah/yq/v4/pkg/yqlib"
	"gopkg.in/op/go-logging.v1"
)

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

func getTestdataPath() string {
	currentDir, _ := os.Getwd()
	return filepath.Join(currentDir, "testdata")
}

func testDirectoryApplyFixHelper(t *testing.T, yamlExpressions *[][]string, directoryPath string) {

	scenarioCount := len(*yamlExpressions)

	for scenario := 1; scenario <= scenarioCount; scenario++ {
		originalFile := fmt.Sprintf("original_yaml_scenario_%d.yml", scenario)
		fixedFile := fmt.Sprintf("fixed_yaml_scenario_%d.yml", scenario)

		originalFilePath := filepath.Join(directoryPath, originalFile)
		fixedFilePath := filepath.Join(directoryPath, fixedFile)

		// create temp file
		tempFile, err := ioutil.TempFile("", originalFile)
		if err != nil {
			panic(err)
		}
		defer os.Remove(tempFile.Name())

		// read original file
		originalFileContent, err := ioutil.ReadFile(originalFilePath)
		if err != nil {
			panic(err)
		}

		// write original file contents to temp file
		err = ioutil.WriteFile(tempFile.Name(), originalFileContent, 0644)
		if err != nil {
			panic(err)
		}

		// make changes to temp file
		h, _ := NewFixHandlerMock()

		filePathFixInfo := make(map[string]*FileFixInfo)
		filePath := tempFile.Name()
		filePathFixInfo[filePath] = &FileFixInfo{
			ContentToAdd:  make([]ContentToAdd, 0),
			LinesToRemove: make([]LinesToRemove, 0),
		}
		fixInfo := filePathFixInfo[filePath]

		for idx, yamlExpression := range (*yamlExpressions)[scenario-1] {
			h.updateFileFixInfo(filePath, yamlExpression, idx, fixInfo)
		}

		err = h.applyFixToFiles(filePathFixInfo)
		assert.NoError(t, err)

		// Check temp file contents
		tempFileContent, err := ioutil.ReadFile(tempFile.Name())
		if err != nil {
			panic(err)
		}

		// Get fixed Yaml file content and check if it is equal to tempFileContent
		fixedFileContent, err := ioutil.ReadFile(fixedFilePath)

		errorMessage := fmt.Sprintf("Content of fixed %s doesn't match content of %s in %s", originalFile, fixedFile, directoryPath)

		assert.Equal(t, string(fixedFileContent), string(tempFileContent), errorMessage)

	}
}

func testDirectoryApplyFix(t *testing.T, directory string) {
	directoryPath := filepath.Join(getTestdataPath(), directory)
	var yamlExpressions [][]string

	switch directory {
	case "insert_scenarios":
		yamlExpressions = [][]string{
			{"select(di==0).spec.containers[0].securityContext.allowPrivilegeEscalation |= false"},

			{"select(di==0).spec.containers[0].securityContext.capabilities.drop += [\"NET_RAW\"]"},

			{"select(di==0).spec.containers[0].securityContext.capabilities.drop += [\"SYS_ADM\"]"},

			{`select(di==0).spec.template.spec.securityContext.allowPrivilegeEscalation |= false | 
			 select(di==0).spec.template.spec.containers[0].securityContext.capabilities.drop += ["NET_RAW"] | 
			 select(di==0).spec.template.spec.containers[0].securityContext.seccompProfile.type |= "RuntimeDefault" | 
			 select(di==0).spec.template.spec.containers[0].securityContext.allowPrivilegeEscalation |= false | 
			 select(di==0).spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem |= true`},

			{"select(di==0).spec.containers[0].securityContext.allowPrivilegeEscalation |= false"},

			{"select(di==0).spec.containers[0].securityContext.capabilities.drop += [\"SYS_ADM\"]"},

			{
				"select(di==0).spec.containers[0].securityContext.allowPrivilegeEscalation |= false",
				"select(di==1).spec.containers[0].securityContext.allowPrivilegeEscalation |= false",
			},
		}

	case "remove_scenarios":
		yamlExpressions = [][]string{
			{"del(select(di==0).spec.containers[0].securityContext)"},

			{"del(select(di==0).spec.containers[1])"},

			{"del(select(di==0).spec.containers[0].securityContext.capabilities.drop[1])"},

			{
				"del(select(di==0).spec.containers[0].securityContext)",
				"del(select(di==1).spec.containers[1])",
			},
		}

	case "replace_scenarios":
		yamlExpressions = [][]string{
			{"select(di==0).spec.containers[0].securityContext.runAsRoot |= false"},

			{`select(di==0).spec.containers[0].securityContext.capabilities.drop[0] |= "SYS_ADM" | 
			 select(di==0).spec.containers[0].securityContext.capabilities.add[0] |= "NET_RAW"`},
		}

	case "hybrid_scenarios":
		yamlExpressions = [][]string{
			{`del(select(di==0).spec.containers[0].securityContext) | 
			 select(di==0).spec.securityContext.runAsRoot |= false`},
		}
	}

	testDirectoryApplyFixHelper(t, &yamlExpressions, directoryPath)
}

func TestFixHandler_applyFixToFile(t *testing.T) {
	// Tests for Insert scenarios
	testDirectoryApplyFix(t, "insert_scenarios")

	// Tests for Removal scenarios
	testDirectoryApplyFix(t, "remove_scenarios")

	// Tests for Replace scenarios
	testDirectoryApplyFix(t, "replace_scenarios")

	// Tests for Hybrid Scenarios
	testDirectoryApplyFix(t, "hybrid_scenarios")

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
			if got := fixPathToValidYamlExpression(tt.args.fixPath, tt.args.value, tt.args.documentIndexInYaml); got != tt.want {
				t.Errorf("fixPathToValidYamlExpression() = %v, want %v", got, tt.want)
			}
		})
	}
}
