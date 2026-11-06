package decrypt

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/kubescape/kubescape/v4/core/pkg/reportcrypto"
	"github.com/spf13/cobra"
)

// DefaultMaxReportSize bounds encrypted report files parsed from disk (100 MiB),
// preventing uncontrolled memory allocation from oversized inputs or decompression bombs (CWE-400).
const DefaultMaxReportSize int64 = 100 * 1024 * 1024

// MaxReportSizeEnvVar is the environment variable that overrides DefaultMaxReportSize.
// Value is parsed as decimal bytes (e.g. "209715200" for 200 MiB).
const MaxReportSizeEnvVar = "KUBESCAPE_MAX_REPORT_SIZE"

var (
	errReportNotRegular = errors.New("report is not a regular file")
	errReportTooLarge   = errors.New("report is too large")
)

// getMaxReportSize resolves the maximum allowed report size in bytes from the CLI
// flag, the KUBESCAPE_MAX_REPORT_SIZE environment variable, or DefaultMaxReportSize.
func getMaxReportSize(flagVal int64) (int64, error) {
	if flagVal > 0 {
		if flagVal == math.MaxInt64 {
			return 0, fmt.Errorf("max-report-size exceeds supported limits")
		}
		return flagVal, nil
	}
	if v, ok := os.LookupEnv(MaxReportSizeEnvVar); ok {
		trimmed := strings.TrimSpace(v)
		if trimmed != "" {
			parsed, err := strconv.ParseInt(trimmed, 10, 64)
			if err != nil || parsed <= 0 || parsed == math.MaxInt64 {
				return 0, fmt.Errorf("invalid %s %q: must be a positive integer", MaxReportSizeEnvVar, v)
			}
			return parsed, nil
		}
	}
	return DefaultMaxReportSize, nil
}

// openReport opens path for reading and rejects non-regular files (such as FIFOs,
// device nodes, or directories). O_NONBLOCK ensures that opening a FIFO without a writer
// fails or returns immediately rather than blocking the process indefinitely.
func openReport(path string) (*os.File, error) {
	file, err := os.OpenFile(filepath.Clean(path), os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	if info.IsDir() {
		file.Close()
		return nil, fmt.Errorf("%q is a directory, not a file", path)
	}
	if !info.Mode().IsRegular() {
		file.Close()
		return nil, fmt.Errorf("%w: %q", errReportNotRegular, path)
	}
	return file, nil
}

// readReportFile returns the contents of the report at path, reading at most
// maxReportSize bytes so that reading remains bounded.
func readReportFile(path string, maxReportSize int64) ([]byte, error) {
	file, err := openReport(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err == nil && info.Size() > maxReportSize {
		return nil, fmt.Errorf("%w: %q exceeds the %d byte limit", errReportTooLarge, path, maxReportSize)
	}

	data, err := io.ReadAll(io.LimitReader(file, maxReportSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxReportSize {
		return nil, fmt.Errorf("%w: %q exceeds the %d byte limit", errReportTooLarge, path, maxReportSize)
	}
	return data, nil
}

var decryptCmdExamples = `
  # Supply the same passphrase that encrypted the report. Hex-encoded key
  # material goes in KUBESCAPE_MASTER_KEY_HEX instead.
  export KUBESCAPE_MASTER_KEY="$(cat master-key.txt)"

  # Decrypt an encrypted report
  kubescape decrypt encrypted-report.json

  # Save the decrypted report to a file
  kubescape decrypt encrypted-report.json > decrypted-report.json
`

func GetDecryptCommand() *cobra.Command {
	var maxReportSize int64

	cmd := &cobra.Command{
		Use:          "decrypt <report.json>",
		Short:        "Decrypt a report produced by kubescape scan --encrypt",
		SilenceUsage: true,
		Long: `Decrypt all encrypted report fields using KUBESCAPE_MASTER_KEY
(or KUBESCAPE_MASTER_KEY_HEX).

The command restores metadata, resources, result raw resources, resource
labels, and resource ID references. The decrypted report is written to
standard output and can be redirected to a file.`,
		Example: decryptCmdExamples,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if cmd.Flags().Changed("max-report-size") && maxReportSize <= 0 {
				return fmt.Errorf("invalid --max-report-size %d: must be greater than 0", maxReportSize)
			}
			limit, err := getMaxReportSize(maxReportSize)
			if err != nil {
				return err
			}

			data, err := readReportFile(args[0], limit)
			if err != nil {
				return fmt.Errorf("failed to read report %q: %w", args[0], err)
			}

			decrypted, err := reportcrypto.DecryptReportFromEnv(data)
			if err != nil {
				return err
			}

			if _, err := fmt.Fprintln(cmd.OutOrStdout(), string(decrypted)); err != nil {
				return fmt.Errorf("failed to write decrypted report: %w", err)
			}

			return nil
		},
	}

	cmd.Flags().Int64Var(&maxReportSize, "max-report-size", 0, "Maximum allowed report file size in bytes (defaults to 100 MiB; can also be overridden with KUBESCAPE_MAX_REPORT_SIZE)")

	return cmd
}
