package version

import (
	"context"

	logger "github.com/kubescape/go-logger"
)

var _ IChecker = &SkipChecker{}

// SkipChecker is a noop checker.
type SkipChecker struct {
}

// NewskipChecker returns a dummy version checker that actually skips the check.
func NewSkipChecker() *SkipChecker {
	return &SkipChecker{}
}

func (v *SkipChecker) CheckLatestVersion(_ context.Context, _ ...CheckRequestOption) error {
	logger.L().Info("Skipping version check")

	return nil
}
