package predict

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// validatePSSOutput protects every local manifest, not just workloads retained
// after namespace/kind filtering. The parser has finished reading by the time
// writeOutput truncates its destination, so an alias otherwise destroys input
// without making the prediction fail.
func validatePSSOutput(output string, paths []string, stdin io.Reader) error {
	if output == "" {
		return nil
	}
	destination, err := os.Stat(output)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("cannot inspect PSS output %q: %w", output, err)
	}
	check := func(source string, info os.FileInfo) error {
		if os.SameFile(destination, info) {
			return fmt.Errorf("PSS output %q would overwrite input manifest %q; choose a different output file", output, source)
		}
		return nil
	}
	for _, path := range paths {
		if path == "-" {
			input := stdin
			if input == nil {
				input = os.Stdin
			}
			if file, ok := input.(*os.File); ok {
				info, err := file.Stat()
				if err != nil {
					return fmt.Errorf("cannot inspect PSS stdin: %w", err)
				}
				if err := check("stdin", info); err != nil {
					return err
				}
			}
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("cannot inspect PSS input %q: %w", path, err)
		}
		if !info.IsDir() {
			if err := check(path, info); err != nil {
				return err
			}
			continue
		}
		entries, err := os.ReadDir(path)
		if err != nil {
			return fmt.Errorf("cannot inspect PSS input directory %q: %w", path, err)
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			switch strings.ToLower(filepath.Ext(entry.Name())) {
			case ".yaml", ".yml", ".json":
			default:
				continue
			}
			source := filepath.Join(path, entry.Name())
			info, err := os.Stat(source)
			if err != nil {
				return fmt.Errorf("cannot inspect PSS input %q: %w", source, err)
			}
			if err := check(source, info); err != nil {
				return err
			}
		}
	}
	return nil
}
