package hostsensorutils

import "github.com/armosec/opa-utils/objectsenvelopes"

type HostSensorHandlerMock struct {
}

func (hshm *HostSensorHandlerMock) Init() error {
	return nil
}

func (hshm *HostSensorHandlerMock) TearDown() error {
	return nil
}

func (hshm *HostSensorHandlerMock) CollectResources() ([]objectsenvelopes.HostSensorDataEnvelope, error) {
	return []objectsenvelopes.HostSensorDataEnvelope{}, nil
}

func (hshm *HostSensorHandlerMock) GetNamespace() string {
	return ""
}
