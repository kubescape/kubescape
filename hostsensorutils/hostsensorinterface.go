package hostsensorutils

import "github.com/armosec/opa-utils/objectsenvelopes"

type IHostSensor interface {
	Init() error
	TearDown() error
	CollectResources() ([]objectsenvelopes.HostSensorDataEnvelope, error)
	GetNamespace() string
}
