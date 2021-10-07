package getter

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/armosec/kubescape/cautils/armotypes"
	"github.com/armosec/kubescape/cautils/opapolicy"
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

func (lp *LoadPolicy) GetFramework(frameworkName string) (*opapolicy.Framework, error) {

	framework := &opapolicy.Framework{}
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
