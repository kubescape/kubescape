package hostsensorutils

type IHostSensor interface {
	Init() error
	TearDown() error
	CollectResources() ([]HostSensorDataEnvelope, error)
}
