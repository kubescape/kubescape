package hostsensorutils

import (
	"context"

	"github.com/kubescape/opa-utils/objectsenvelopes/hostsensor"
	"github.com/kubescape/opa-utils/reporthandling/apis"
)

// HostSensorHandlerMock is a noop sensor when the host scanner is disabled.
type HostSensorHandlerMock struct {
}

// NewHostSensorHandlerMock yields a dummy host sensor.
func NewHostSensorHandlerMock() *HostSensorHandlerMock {
	return &HostSensorHandlerMock{}
}

func (hshm *HostSensorHandlerMock) Init(_ context.Context) error {
	return nil
}

func (hshm *HostSensorHandlerMock) TearDown() error {
	return nil
}

func (hshm *HostSensorHandlerMock) CollectResources(_ context.Context) ([]hostsensor.HostSensorDataEnvelope, map[string]apis.StatusInfo, error) {
	return []hostsensor.HostSensorDataEnvelope{}, nil, nil
}

func (hshm *HostSensorHandlerMock) GetNamespace() string {
	return ""
}
