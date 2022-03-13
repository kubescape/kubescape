package hostsensorutils

import (
	"github.com/armosec/opa-utils/objectsenvelopes/hostsensor"
)

type HostSensorHandlerMock struct {
}

func (hshm *HostSensorHandlerMock) Init() error {
	return nil
}

func (hshm *HostSensorHandlerMock) TearDown() error {
	return nil
}

func (hshm *HostSensorHandlerMock) CollectResources() ([]hostsensor.HostSensorDataEnvelope, error) {
	return []hostsensor.HostSensorDataEnvelope{}, nil
}

func (hshm *HostSensorHandlerMock) GetNamespace() string {
	return ""
}
