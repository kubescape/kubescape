package hostsensorutils

import (
	"context"

	"github.com/kubescape/opa-utils/objectsenvelopes/hostsensor"
	"github.com/kubescape/opa-utils/reporthandling/apis"
)

type SyscallEvent struct {
	PID            int32
	PodUID         string
	SyscallID      int32
	CapabilityName string
}

type IHostSensor interface {
	Init(ctx context.Context) error
	TearDown() error
	CollectResources(context.Context) ([]hostsensor.HostSensorDataEnvelope, map[string]apis.StatusInfo, error)
	StreamTelemetry(ctx context.Context) (<-chan SyscallEvent, error)
}
