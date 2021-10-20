package getter

import (
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
		gs: gitregostore.InitDefaultGitRegoStore(),
	}
}

func (drp *DownloadReleasedPolicy) GetControl(policyName string) (*reporthandling.Control, error) {
	control, err := drp.gs.GetOPAControlByName(policyName)
	if err != nil {
		control, err = drp.gs.GetOPAControlByID(policyName)
		if err != nil {
			return nil, err
		}
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
