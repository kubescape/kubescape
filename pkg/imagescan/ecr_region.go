package imagescan

import (
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/ecr"
)

// ecrRegistryRegion is called only after ecrRegistryAccount validates the
// hostname. Standard/FIPS hosts place the region after dkr.ecr; dual-stack
// hosts (including China) place it after dkr-ecr instead.
func ecrRegistryRegion(registry string) string {
	parts := strings.Split(registry, ".")
	if parts[1] == "dkr" {
		return parts[3]
	}
	return parts[2]
}

// Per-call options avoid mutating the shared client when a batch contains
// images from several regions. Pagination must use the same image region.
func ecrImageRegion(registry string) func(*ecr.Options) {
	region := ecrRegistryRegion(registry)
	return func(options *ecr.Options) {
		options.Region = region
	}
}
