package hostsensorutils

import (
	"encoding/json"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"
)

type HostSensorDataEnvelope struct {
	schema.GroupVersionResource
	NodeName string          `json:"nodeName"`
	Data     json.RawMessage `json:"data"`
}

func (hsde *HostSensorDataEnvelope) SetNamespace(string) {

}

func (hsde *HostSensorDataEnvelope) SetName(val string) {
	hsde.NodeName = val
}

func (hsde *HostSensorDataEnvelope) SetKind(val string) {
	hsde.Resource = val

}

func (hsde *HostSensorDataEnvelope) SetWorkload(val map[string]interface{}) { //deprecated
	hsde.Data, _ = json.Marshal(val)
}

func (hsde *HostSensorDataEnvelope) SetObject(val map[string]interface{}) {
	hsde.Data, _ = json.Marshal(val)
}

func (hsde *HostSensorDataEnvelope) GetNamespace() string {
	return ""
}

func (hsde *HostSensorDataEnvelope) GetName() string {
	return hsde.NodeName
}

func (hsde *HostSensorDataEnvelope) GetKind() string {
	return hsde.Resource
}

func (hsde *HostSensorDataEnvelope) GetApiVersion() string {
	return hsde.Version
}

func (hsde *HostSensorDataEnvelope) GetWorkload() map[string]interface{} { // DEPRECATED
	res := map[string]interface{}{}
	json.Unmarshal(hsde.Data, &res)
	return res
}

func (hsde *HostSensorDataEnvelope) GetObject() map[string]interface{} {
	res := map[string]interface{}{}
	json.Unmarshal(hsde.Data, &res)
	return res
}

func (hsde *HostSensorDataEnvelope) GetID() string { // -> <api-group>/<api-version>/<kind>/<name>
	return fmt.Sprintf("%s/%s/%s/%s", hsde.Group, hsde.GetApiVersion(), hsde.GetKind(), hsde.GetName())
}
