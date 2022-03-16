package hostsensorutils

import (
	"github.com/armosec/opa-utils/objectsenvelopes/hostsensor"
	"github.com/armosec/opa-utils/reporthandling/apis"
)

type IHostSensor interface {
	Init() error
	TearDown() error
	CollectResources(map[string]apis.StatusInfo) ([]hostsensor.HostSensorDataEnvelope, error)
	GetNamespace() string
}
