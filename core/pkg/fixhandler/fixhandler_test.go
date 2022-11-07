package fixhandler

import (
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

func onlineBoutiquePath() string {
	o, _ := os.Getwd()
	return filepath.Join(filepath.Dir(o), "..", "..", "examples", "online-boutique")
}

func TestFixHandler_applyFixToFile(t *testing.T) {
	originalFilePath := filepath.Join(onlineBoutiquePath(), "adservice.yaml")
	// create temp file
	tempFile, err := ioutil.TempFile("", "adservice.yaml")
	if err != nil {
		panic(err)
	}
	defer os.Remove(tempFile.Name())

	// read original file
	b, err := ioutil.ReadFile(originalFilePath)
	if err != nil {
		panic(err)
	}
	assert.NotContains(t, string(b), "readOnlyRootFilesystem: true")

	// write original file contents to temp file
	err = ioutil.WriteFile(tempFile.Name(), b, 0644)
	if err != nil {
		panic(err)
	}

	// make changes to temp file
	h, _ := NewFixHandlerMock()
	yamlExpression := "select(di==0).spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem |= true"
	err = h.applyFixToFile(tempFile.Name(), yamlExpression)
	assert.NoError(t, err)

	// Check temp file contents
	b, err = ioutil.ReadFile(tempFile.Name())
	if err != nil {
		panic(err)
	}
	assert.Contains(t, string(b), "readOnlyRootFilesystem: true")
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
