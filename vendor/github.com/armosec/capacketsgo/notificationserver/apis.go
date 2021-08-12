package notificationserver

// server paths
const (
	PathWebsocketV1 = "/v1/waitfornotification"
	PathRESTV1      = "/v1/sendnotification"
)

const (
	TargetCustomer  = "customerGUID"
	TargetCluster   = "clusterName"
	TargetComponent = "clusterComponent"
)

const (
	TargetComponentPostureValue = "PolicyValidator"
	TargetComponentLoggerValue  = "Logger"
)
