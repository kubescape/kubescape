package reporter

import (
	"context"

	"github.com/kubescape/kubescape/v2/core/cautils"
)

// IReport knows how to upload posture reports.
type IReport interface {
	// Submit a report.
	Submit(ctx context.Context, opaSessionObj *cautils.OPASessionObj) error

	// SetCustomerGUID sets the user account.
	SetCustomerGUID(customerGUID string)

	// SetClusterName sets the name of the cluster being reported.
	SetClusterName(clusterName string)

	// DisplayReportURL outputs a message upon successful upload of the reports.
	DisplayReportURL()

	// GetURL returns the URL to view a report on Kubescape's SaaS frontend.
	GetURL() string
}
