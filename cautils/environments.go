package cautils

import (
	"os"
)

// CA environment vars
var (
	CustomerGUID          = ""
	ClusterName           = ""
	EventReceiverURL      = ""
	NotificationServerURL = ""
	DashboardBackendURL   = ""
	RestAPIPort           = "4001"
)

func SetupDefaultEnvs() {
	if os.Getenv("CA_DASHBOARD_BACKEND") == "" {
		os.Setenv("CA_DASHBOARD_BACKEND", "https://dashbe.eudev3.cyberarmorsoft.com") // use prod
	}
	if os.Getenv("CA_CUSTOMER_GUID") == "" {
		os.Setenv("CA_CUSTOMER_GUID", "11111111-1111-1111-1111-111111111111")
	}
}
