package hostsensorutils

type HostSensorHandlerMock struct {
}

func (hshm *HostSensorHandlerMock) Init() error {
	return nil
}

func (hshm *HostSensorHandlerMock) TearDown() error {
	return nil
}

func (hshm *HostSensorHandlerMock) CollectResources() ([]HostSensorDataEnvelope, error) {
	return []HostSensorDataEnvelope{}, nil
}
