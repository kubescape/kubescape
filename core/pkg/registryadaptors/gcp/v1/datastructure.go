package v1

import (
	"github.com/kubescape/kubescape/v2/core/cautils/getter"
)

type GCPAdaptor struct {
	GCPCloudAPI *getter.GCPCloudAPI
}

type Mock struct {
	Name             string
	Notename         string
	CvssScore        float32
	CreatedTime      int64
	UpdatedTime      int64
	Type             string
	ShortDescription string
	AffectedCPEURI   string
	AffectedPackage  string
	FixAvailable     bool
	AffectedVersion  string
	FixedVersion     string
}
