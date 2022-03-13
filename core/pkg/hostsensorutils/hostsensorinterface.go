package hostsensorutils

import "github.com/armosec/opa-utils/objectsenvelopes/hostsensor"

type IHostSensor interface {
	Init() error
	TearDown() error
	CollectResources() ([]hostsensor.HostSensorDataEnvelope, error)
	GetNamespace() string
}
