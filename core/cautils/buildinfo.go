package cautils

import (
	"os"

	"github.com/kubescape/backend/pkg/versioncheck"
)

var BuildNumber string
var Client string

func init() {
	if BuildNumber != "" {
		versioncheck.BuildNumber = BuildNumber
	} else {
		versioncheck.BuildNumber = os.Getenv("RELEASE")
	}
	if Client != "" {
		versioncheck.Client = Client
	}
}
