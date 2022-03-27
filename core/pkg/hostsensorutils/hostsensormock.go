package hostsensorutils

import (
	"github.com/armosec/opa-utils/objectsenvelopes/hostsensor"
	"github.com/armosec/opa-utils/reporthandling/apis"
)

type HostSensorHandlerMock struct {
}

func (hshm *HostSensorHandlerMock) Init() error {
	return nil
}

func (hshm *HostSensorHandlerMock) TearDown() error {
	return nil
}

func (hshm *HostSensorHandlerMock) CollectResources() ([]hostsensor.HostSensorDataEnvelope, map[string]apis.StatusInfo, error) {
	return []hostsensor.HostSensorDataEnvelope{}, nil, nil
}

func (hshm *HostSensorHandlerMock) GetNamespace() string {
	return ""
}
