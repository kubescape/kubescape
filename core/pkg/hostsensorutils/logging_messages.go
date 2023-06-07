package hostsensorutils

// messages used for warnings
var (
	failedToGetData                     = "failed to get data"
	failedToTeardownNamespace           = "failed to teardown Namespace"
	oneHostSensorPodIsUnabledToSchedule = "One host-sensor pod is unable to schedule on node. We will fail to collect the data from this node"
	failedToWatchOverDaemonSetPods      = "failed to watch over DaemonSet pods"
	failedToValidateHostSensorPodStatus = "failed to validate host-scanner pods status"
)
