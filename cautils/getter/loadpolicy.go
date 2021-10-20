package getter

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/opa-utils/reporthandling"
)

// =======================================================================================================================
// ============================================== LoadPolicy =============================================================
// =======================================================================================================================
const DefaultLocalStore = ".kubescape"

// Load policies from a local repository
type LoadPolicy struct {
	filePath string
}

func NewLoadPolicy(filePath string) *LoadPolicy {
	return &LoadPolicy{
		filePath: filePath,
	}
}

func (lp *LoadPolicy) GetControl(controlName string) (*reporthandling.Control, error) {

	control := &reporthandling.Control{}
	f, err := os.ReadFile(lp.filePath)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(f, control)
	if controlName != "" && !strings.EqualFold(controlName, control.Name) && !strings.EqualFold(controlName, control.ControlID) {
		return nil, fmt.Errorf("control from file not matching")
	}
	return control, err
}

func (lp *LoadPolicy) GetFramework(frameworkName string) (*reporthandling.Framework, error) {

	framework := &reporthandling.Framework{}
	f, err := os.ReadFile(lp.filePath)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(f, framework)
	if frameworkName != "" && !strings.EqualFold(frameworkName, framework.Name) {
		return nil, fmt.Errorf("framework from file not matching")
	}
	return framework, err
}

func (lp *LoadPolicy) GetExceptions(customerGUID, clusterName string) ([]armotypes.PostureExceptionPolicy, error) {

	exception := []armotypes.PostureExceptionPolicy{}
	f, err := os.ReadFile(lp.filePath)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(f, &exception)
	return exception, err
}
