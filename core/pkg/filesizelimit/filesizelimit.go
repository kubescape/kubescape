// Package filesizelimit centralizes parsing and configuration of file size limits
// across Kubescape components (cautils, fixhandler, locationresolver) to ensure consistent
// bounding against uncontrolled memory allocation and decompression bombs (CWE-400).
package filesizelimit

import (
	"math"
	"os"
	"strconv"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

const (
	// DefaultMaxFileSize is the default per-file read cap (32 MiB).
	DefaultMaxFileSize int64 = 32 << 20

	// MaxFileSizeEnvVar is the environment variable used to override DefaultMaxFileSize.
	MaxFileSizeEnvVar = "KUBESCAPE_MAX_FILE_SIZE"
)

// GetMaxFileSize returns the configured per-file size limit in bytes.
// It reads MaxFileSizeEnvVar as decimal bytes when set, otherwise defaults to
// DefaultMaxFileSize. Non-positive, unparsable, or math.MaxInt64 values fall
// back to the default so operations stay bounded and limit+1 does not overflow.
func GetMaxFileSize() int64 {
	if v, ok := os.LookupEnv(MaxFileSizeEnvVar); ok {
		trimmed := strings.TrimSpace(v)
		if trimmed != "" {
			if parsed, err := strconv.ParseInt(trimmed, 10, 64); err == nil && parsed > 0 && parsed != math.MaxInt64 {
				return parsed
			}
			logger.L().Warning("invalid KUBESCAPE_MAX_FILE_SIZE, using default", helpers.String("value", v), helpers.Int("default", int(DefaultMaxFileSize)))
		}
	}
	return DefaultMaxFileSize
}
