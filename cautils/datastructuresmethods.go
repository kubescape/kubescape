package cautils

import (
	"encoding/json"

	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/util"
)

func (data *RegoInputData) SetControlsInputs(controlsInputs map[string][]string) {
	data.PostureControlInputs = controlsInputs
}

func (data *RegoInputData) TOStorage() (storage.Store, error) {
	var jsonObj map[string]interface{}
	bytesData, err := json.Marshal(*data)
	if err != nil {
		return nil, err
	}
	// glog.Infof("RegoDependenciesData: %s", bytesData)
	if err := util.UnmarshalJSON(bytesData, &jsonObj); err != nil {
		return nil, err
	}
	return inmem.NewFromObject(jsonObj), nil
}
