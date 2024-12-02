package getter

import (
	"fmt"
	"strings"

	"github.com/armosec/armoapi-go/armotypes"

	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/attacktrack/v1alpha1"

	"github.com/kubescape/regolibrary/v2/gitregostore"
)

// =======================================================================================================================
// ======================================== DownloadReleasedPolicy =======================================================
// =======================================================================================================================
var (
	_ IPolicyGetter         = &DownloadReleasedPolicy{}
	_ IExceptionsGetter     = &DownloadReleasedPolicy{}
	_ IAttackTracksGetter   = &DownloadReleasedPolicy{}
	_ IControlsInputsGetter = &DownloadReleasedPolicy{}
)

// Use gitregostore to get policies from github release
type DownloadReleasedPolicy struct {
	gs *gitregostore.GitRegoStore
}

func NewDownloadReleasedPolicy() *DownloadReleasedPolicy {
	return &DownloadReleasedPolicy{
		gs: gitregostore.NewGitRegoStoreV2(-1),
	}
}

func (drp *DownloadReleasedPolicy) GetControl(ID string) (*reporthandling.Control, error) {
	var control *reporthandling.Control
	var err error

	control, err = drp.gs.GetOPAControlByID(ID)
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

func (drp *DownloadReleasedPolicy) GetFrameworks() ([]reporthandling.Framework, error) {
	frameworks, err := drp.gs.GetOPAFrameworks()
	if err != nil {
		return nil, err
	}
	return frameworks, err
}

func (drp *DownloadReleasedPolicy) ListFrameworks() ([]string, error) {
	return drp.gs.GetOPAFrameworksNamesList()
}

func (drp *DownloadReleasedPolicy) ListControls() ([]string, error) {
	controlsIDsList, err := drp.gs.GetOPAControlsIDsList()
	if err != nil {
		return []string{}, err
	}
	controlsNamesList, err := drp.gs.GetOPAControlsNamesList()
	if err != nil {
		return []string{}, err
	}
	controls, err := drp.gs.GetOPAControls()
	if err != nil {
		return []string{}, err
	}
	var controlsFrameworksList [][]string
	for _, control := range controls {
		controlsFrameworksList = append(controlsFrameworksList, drp.gs.GetOpaFrameworkListByControlID(control.ControlID))
	}
	controlsNamesWithIDsandFrameworksList := make([]string, len(controlsIDsList))
	// by design all slices have the same lengt
	for i := range controlsIDsList {
		controlsNamesWithIDsandFrameworksList[i] = fmt.Sprintf("%v|%v|%v", controlsIDsList[i], controlsNamesList[i], strings.Join(controlsFrameworksList[i], ", "))
	}
	return controlsNamesWithIDsandFrameworksList, nil
}

func (drp *DownloadReleasedPolicy) GetControlsInputs(clusterName string) (map[string][]string, error) {
	defaultConfigInputs, err := drp.gs.GetDefaultConfigInputs()
	if err != nil {
		return nil, err
	}
	return defaultConfigInputs.Settings.PostureControlInputs, err
}

func (drp *DownloadReleasedPolicy) GetAttackTracks() ([]v1alpha1.AttackTrack, error) {
	attackTracks, err := drp.gs.GetAttackTracks()
	if err != nil {
		return nil, err
	}
	return attackTracks, err
}

func (drp *DownloadReleasedPolicy) SetRegoObjects() error {
	fwNames, err := drp.gs.GetOPAFrameworksNamesList()
	if len(fwNames) != 0 && err == nil {
		return nil
	}
	return drp.gs.SetRegoObjects()
}

func (drp *DownloadReleasedPolicy) GetExceptions(clusterName string) ([]armotypes.PostureExceptionPolicy, error) {
	exceptions, err := drp.gs.GetSystemPostureExceptionPolicies()
	if err != nil {
		return nil, err
	}
	return exceptions, nil
}
