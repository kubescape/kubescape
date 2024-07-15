package getter

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/attacktrack/v1alpha1"
)

// =======================================================================================================================
// ============================================== LoadPolicy =============================================================
// =======================================================================================================================
var (
	DefaultLocalStore = getCacheDir()

	ErrNotImplemented       = errors.New("feature is currently not supported")
	ErrNotFound             = errors.New("name not found")
	ErrNameRequired         = errors.New("missing required input framework name")
	ErrIDRequired           = errors.New("missing required input control ID")
	ErrFrameworkNotMatching = errors.New("framework from file not matching")
	ErrControlNotMatching   = errors.New("control from file not matching")
)

var (
	_ IPolicyGetter         = &LoadPolicy{}
	_ IExceptionsGetter     = &LoadPolicy{}
	_ IAttackTracksGetter   = &LoadPolicy{}
	_ IControlsInputsGetter = &LoadPolicy{}
)

func getCacheDir() string {
	defaultDirPath := ".kubescape"
	if homeDir, err := os.UserHomeDir(); err == nil {
		defaultDirPath = filepath.Join(homeDir, defaultDirPath)
	}
	return defaultDirPath
}

// LoadPolicy loads policies from a local repository.
type LoadPolicy struct {
	filePaths []string
}

// NewLoadPolicy builds a LoadPolicy.
func NewLoadPolicy(filePaths []string) *LoadPolicy {
	return &LoadPolicy{
		filePaths: filePaths,
	}
}

// GetControl returns a control from the policy file.
func (lp *LoadPolicy) GetControl(controlID string) (*reporthandling.Control, error) {
	if controlID == "" {
		return nil, ErrIDRequired
	}

	// NOTE: this assumes that only the first path contains either a valid control descriptor or a framework descriptor
	filePath := lp.filePath()
	buf, err := os.ReadFile(filePath)

	if err != nil {
		return nil, err
	}

	// check if the file is a control descriptor: a ControlID field is populated.
	var control reporthandling.Control
	if err = json.Unmarshal(buf, &control); err == nil && control.ControlID != "" {
		if strings.EqualFold(controlID, control.ControlID) {
			return &control, nil
		}

		return nil, fmt.Errorf("controlID: %s: %w", controlID, ErrControlNotMatching)
	}

	// check if the file is a framework descriptor
	var framework reporthandling.Framework
	if err = json.Unmarshal(buf, &framework); err != nil {
		return nil, err
	}

	for _, toPin := range framework.Controls {
		ctrl := toPin

		if strings.EqualFold(ctrl.ControlID, controlID) {
			return &ctrl, nil
		}
	}

	return nil, fmt.Errorf("controlID: %s: %w", controlID, ErrControlNotMatching)
}

// GetFramework retrieves a framework configuration from the policy paths.
func (lp *LoadPolicy) GetFramework(frameworkName string) (*reporthandling.Framework, error) {
	if frameworkName == "" {
		return nil, ErrNameRequired
	}

	for _, filePath := range lp.filePaths {
		buf, err := os.ReadFile(filePath)
		if err != nil {
			return nil, err
		}

		var framework reporthandling.Framework
		if err = json.Unmarshal(buf, &framework); err != nil {
			return nil, err
		}

		if strings.EqualFold(frameworkName, framework.Name) {
			return &framework, nil
		}
	}

	return nil, fmt.Errorf("framework: %s: %w", frameworkName, ErrFrameworkNotMatching)
}

// GetFrameworks returns all configured framework descriptors.
func (lp *LoadPolicy) GetFrameworks() ([]reporthandling.Framework, error) {
	frameworks := make([]reporthandling.Framework, 0, 10)
	seenFws := make(map[string]struct{})

	for _, f := range lp.filePaths {
		buf, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}

		var framework reporthandling.Framework
		if err = json.Unmarshal(buf, &framework); err != nil {
			// ignore invalid framework files
			continue
		}

		// dedupe
		_, alreadyLoaded := seenFws[framework.Name]
		if alreadyLoaded {
			continue
		}

		seenFws[framework.Name] = struct{}{}
		frameworks = append(frameworks, framework)
	}

	return frameworks, nil
}

// ListFrameworks lists the names of all configured frameworks in this policy.
func (lp *LoadPolicy) ListFrameworks() ([]string, error) {
	frameworkNames := make([]string, 0, 10)

	for _, f := range lp.filePaths {
		buf, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}

		var framework reporthandling.Framework
		if err := json.Unmarshal(buf, &framework); err != nil {
			continue
		}

		if framework.Name == "" || contains(frameworkNames, framework.Name) {
			continue
		}

		frameworkNames = append(frameworkNames, framework.Name)
	}

	return frameworkNames, nil
}

// ListControls returns the list of controls for this framework.
//
// At this moment, controls are listed for one single configured framework.
func (lp *LoadPolicy) ListControls() ([]string, error) {
	controlIDs := make([]string, 0, 100)
	filePath := lp.filePath()
	buf, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var framework reporthandling.Framework
	if err = json.Unmarshal(buf, &framework); err != nil {
		return nil, err
	}

	for _, ctrl := range framework.Controls {
		controlIDs = append(controlIDs, ctrl.ControlID)
	}

	return controlIDs, nil
}

// GetExceptions retrieves configured exceptions.
//
// NOTE: the cluster parameter is not used at this moment.
func (lp *LoadPolicy) GetExceptions(_ /* clusterName */ string) ([]armotypes.PostureExceptionPolicy, error) {
	// NOTE: this assumes that the first path contains a valid exceptions descriptor
	filePath := lp.filePath()

	buf, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	exception := make([]armotypes.PostureExceptionPolicy, 0, 300)
	err = json.Unmarshal(buf, &exception)

	return exception, err
}

// GetControlsInputs retrieves the map of control configs.
//
// NOTE: the cluster parameter is not used at this moment.
func (lp *LoadPolicy) GetControlsInputs(_ /* clusterName */ string) (map[string][]string, error) {
	// NOTE: this assumes that only the first path contains a valid control inputs descriptor
	filePath := lp.filePath()
	fileName := filepath.Base(filePath)

	buf, err := os.ReadFile(filePath)
	if err != nil {
		formattedError := fmt.Errorf(
			`Error opening %s file, "controls-config" will be downloaded from ARMO management portal`,
			fileName,
		)

		return nil, formattedError
	}

	controlInputs := make(map[string][]string, 100) // from armotypes.Settings.PostureControlInputs
	if err = json.Unmarshal(buf, &controlInputs); err != nil {
		formattedError := fmt.Errorf(
			`Error reading %s file, %v, "controls-config" will be downloaded from ARMO management portal`,
			fileName, err,
		)

		return nil, formattedError
	}

	return controlInputs, nil
}

// GetAttackTracks yields the attack tracks from a config file.
func (lp *LoadPolicy) GetAttackTracks() ([]v1alpha1.AttackTrack, error) {
	attackTracks := make([]v1alpha1.AttackTrack, 0, 20)

	buf, err := os.ReadFile(lp.filePath())
	if err != nil {
		return nil, err
	}

	if err = json.Unmarshal(buf, &attackTracks); err != nil {
		return nil, err
	}

	return attackTracks, nil
}

// temporary support for a list of files
func (lp *LoadPolicy) filePath() string {
	if len(lp.filePaths) > 0 {
		return lp.filePaths[0]
	}
	return ""
}
