package hostsensorutils

import (
	"github.com/kubescape/opa-utils/objectsenvelopes/hostsensor"
	"github.com/kubescape/opa-utils/reporthandling/apis"
)

type IHostSensor interface {
	Init() error
	TearDown() error
	CollectResources() ([]hostsensor.HostSensorDataEnvelope, map[string]apis.StatusInfo, error)
	GetNamespace() string
}
