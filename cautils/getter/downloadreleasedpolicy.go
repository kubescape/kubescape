package getter

import (
	"strings"

	"github.com/armosec/opa-utils/gitregostore"
	"github.com/armosec/opa-utils/reporthandling"
)

// =======================================================================================================================
// ======================================== DownloadReleasedPolicy =======================================================
// =======================================================================================================================

// Download released version
type DownloadReleasedPolicy struct {
	gs *gitregostore.GitRegoStore
}

func NewDownloadReleasedPolicy() *DownloadReleasedPolicy {
	return &DownloadReleasedPolicy{
		gs: gitregostore.InitDefaultGitRegoStore(-1),
	}
}

// Return control per name/id using ARMO api
func (drp *DownloadReleasedPolicy) GetControl(policyName string) (*reporthandling.Control, error) {
	var control *reporthandling.Control
	var err error
	if strings.HasPrefix(policyName, "C-") || strings.HasPrefix(policyName, "c-") {
		control, err = drp.gs.GetOPAControlByID(policyName)
	} else {
		control, err = drp.gs.GetOPAControlByName(policyName)
	}
	if err != nil {
		return nil, err
	}
	return control, nil
}

func (drp *DownloadReleasedPolicy) GetFramework(name string) (*reporthandling.Framework, error) {
	framework, err := drp.gs.GetOPAFrameworkByName(name)
	if err != nil {
		return nil, err
	}
	return framework, err
}
