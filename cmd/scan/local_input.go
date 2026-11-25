package scan

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/filesizelimit"
)

// ErrStdinTooLarge is returned when manifest input read from stdin exceeds the
// configured per-file size limit.
var ErrStdinTooLarge = errors.New("stdin input exceeds maximum allowed size")

const (
	// stdinManifestDirPattern names the private directory that holds the staged
	// stdin manifest.
	stdinManifestDirPattern = "kubescape-stdin-*"
	// stdinManifestName is the file name every staged stdin manifest gets, so
	// reports name the input "stdin.yaml" rather than a random temporary name.
	stdinManifestName = "stdin.yaml"
)

type scanLocalInputOptions struct {
	FirstInputArg    int
	FilePath         string
	RejectMixedStdin bool
}

// prepareScanLocalInput normalizes and prepares scan inputs from positional arguments
// or flags, staging standard input into a temporary file when "-" is specified as the
// manifest source. The staged file is always named "stdin.yaml", inside a temporary
// directory of its own, so reports show a stable name. It returns a cleanup function
// to remove any allocated temporary files.
// When stdin is a regular file (e.g. redirected from a file on disk), its FileInfo is
// preserved on scanInfo.OriginalStdinInfo to enable output safety collision detection.
func prepareScanLocalInput(stdin io.Reader, args []string, scanInfo *cautils.ScanInfo, opts scanLocalInputOptions) (func(), error) {
	cleanup := func() {}
	if opts.FirstInputArg >= len(args) {
		if opts.FilePath != "" && len(scanInfo.InputPatterns) == 0 {
			scanInfo.InputPatterns = []string{opts.FilePath}
		}
		return cleanup, nil
	}

	if opts.FilePath != "" {
		return cleanup, fmt.Errorf("usage: use either --file-path or positional input paths, not both")
	}

	inputs := args[opts.FirstInputArg:]
	if opts.RejectMixedStdin && len(inputs) > 1 {
		for _, input := range inputs {
			if input == "-" {
				return cleanup, fmt.Errorf("usage: stdin input '-' cannot be combined with other input paths")
			}
		}
	}

	if inputs[0] != "-" {
		scanInfo.InputPatterns = inputs
		return cleanup, nil
	}

	var suppliedStdinInfo os.FileInfo
	if file, ok := stdin.(*os.File); ok && file != nil {
		if stat, err := file.Stat(); err == nil && stat.Mode().IsRegular() {
			scanInfo.OriginalStdinInfo = stat
			suppliedStdinInfo = stat
		}
	} else if stat, err := os.Stdin.Stat(); err == nil && stat.Mode().IsRegular() {
		scanInfo.OriginalStdinInfo = stat
	}

	limit := filesizelimit.GetMaxFileSize()
	if suppliedStdinInfo != nil && suppliedStdinInfo.Size() > limit {
		return cleanup, stdinTooLargeError(limit)
	}

	// The manifest goes into a directory of its own, so it can have a fixed
	// name that reports show instead of a random temporary one.
	stagingDir, err := os.MkdirTemp("", stdinManifestDirPattern)
	if err != nil {
		return cleanup, err
	}
	cleanup = func() {
		_ = os.RemoveAll(stagingDir)
	}

	tempFile, err := os.OpenFile(filepath.Join(stagingDir, stdinManifestName), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		cleanup()
		return func() {}, err
	}

	n, err := io.Copy(tempFile, io.LimitReader(stdin, limit+1))
	if err != nil {
		_ = tempFile.Close()
		cleanup()
		return func() {}, err
	}
	if n > limit {
		_ = tempFile.Close()
		cleanup()
		return func() {}, stdinTooLargeError(limit)
	}
	if err := tempFile.Close(); err != nil {
		cleanup()
		return func() {}, err
	}
	scanInfo.InputPatterns = []string{tempFile.Name()}
	return cleanup, nil
}

func stdinTooLargeError(limit int64) error {
	return fmt.Errorf("%w: stdin input exceeds the %d byte limit (override with %s)", ErrStdinTooLarge, limit, filesizelimit.MaxFileSizeEnvVar)
}
