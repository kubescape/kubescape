package cautils

const (
	HostSensorStatus    = "hostSensor"
	CloudProviderStatus = "cloudProvider"
)

var CloudResources = []string{"ClusterDescribe"}

var HostSensorResources = []string{"KubeletConfiguration", "KubeletCommandLine"}
