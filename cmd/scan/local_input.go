package scan

import (
	"fmt"
	"io"
	"os"

	"github.com/kubescape/kubescape/v4/core/cautils"
)

const stdinManifestTempPattern = "tmp-kubescape*.yaml"

type scanLocalInputOptions struct {
	FirstInputArg    int
	FilePath         string
	RejectMixedStdin bool
}

// prepareScanLocalInput normalizes and prepares scan inputs from positional arguments
// or flags, staging standard input into a temporary file when "-" is specified as the
// manifest source. It returns a cleanup function to remove any allocated temporary files.
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

	if file, ok := stdin.(*os.File); ok && file != nil {
		if stat, err := file.Stat(); err == nil && stat.Mode().IsRegular() {
			scanInfo.OriginalStdinInfo = stat
		}
	} else if stat, err := os.Stdin.Stat(); err == nil && stat.Mode().IsRegular() {
		scanInfo.OriginalStdinInfo = stat
	}

	tempFile, err := os.CreateTemp("", stdinManifestTempPattern)
	if err != nil {
		return cleanup, err
	}
	cleanup = func() {
		_ = os.Remove(tempFile.Name())
	}

	if _, err := io.Copy(tempFile, stdin); err != nil {
		_ = tempFile.Close()
		cleanup()
		return func() {}, err
	}
	if err := tempFile.Close(); err != nil {
		cleanup()
		return func() {}, err
	}
	scanInfo.InputPatterns = []string{tempFile.Name()}
	return cleanup, nil
}
