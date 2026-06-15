package getter

import (
	_ "embed"
	encjson "encoding/json"

	"github.com/armosec/armoapi-go/armotypes"
)

//go:generate curl -sSfL https://github.com/kubescape/regolibrary/releases/latest/download/default-config-inputs.json -o resources/default-config-inputs.json
//go:embed resources/default-config-inputs.json
var defaultConfigInputsData []byte

// DefaultControlInputs returns the bundled regolibrary default control
// configurations. It is used as a fallback when the configured control
// inputs source (Kubescape Cloud, ControlInput CRD, or the regolibrary
// GitHub release) could not be reached, so config-dependent controls are
// still evaluated against sane defaults instead of an empty configuration.
func DefaultControlInputs() (map[string][]string, error) {
	var customerConfig armotypes.CustomerConfig
	if err := encjson.Unmarshal(defaultConfigInputsData, &customerConfig); err != nil {
		return nil, err
	}
	return customerConfig.Settings.PostureControlInputs, nil
}
