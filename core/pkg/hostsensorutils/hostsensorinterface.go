package hostsensorutils

import (
	"context"

	"github.com/kubescape/opa-utils/objectsenvelopes/hostsensor"
	"github.com/kubescape/opa-utils/reporthandling/apis"
)

type IHostSensor interface {
	Init(ctx context.Context) error
	TearDown() error
	CollectResources(context.Context) ([]hostsensor.HostSensorDataEnvelope, map[string]apis.StatusInfo, error)
	GetNamespace() string
}
