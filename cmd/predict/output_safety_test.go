package predict

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const outputSafetyManifest = `apiVersion: v1
kind: Pod
metadata:
  name: unsafe
  namespace: prod
spec:
  containers:
  - name: app
    image: nginx
    securityContext:
      privileged: true
`

func TestPSSReportCannotOverwriteInputManifests(t *testing.T) {
	for _, format := range pssFormats {
		for _, inputKind := range []string{"file", "directory", "uppercase extension", "second input", "filtered namespace", "unsupported kind", "symlink output", "hardlink output", "symlink input"} {
			t.Run(format+"/"+inputKind, func(t *testing.T) {
				dir := t.TempDir()
				input := filepath.Join(dir, "workload.yaml")
				if inputKind == "uppercase extension" {
					input = filepath.Join(dir, "workload.YAML")
				}
				manifest := outputSafetyManifest
				if inputKind == "unsupported kind" {
					manifest = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: settings\n"
				}
				require.NoError(t, os.WriteFile(input, []byte(manifest), 0o600))
				before, err := os.Stat(input)
				require.NoError(t, err)
				paths, output := []string{input}, input
				flags := &pssFlags{level: "Baseline", format: format, output: output}
				switch inputKind {
				case "directory", "uppercase extension":
					paths = []string{dir}
				case "second input":
					other := filepath.Join(dir, "other.yaml")
					require.NoError(t, os.WriteFile(other, []byte(outputSafetyManifest), 0o600))
					paths = []string{other, input}
				case "filtered namespace":
					flags.namespace = "dev"
				case "symlink output":
					output = filepath.Join(dir, "report.json")
					require.NoError(t, os.Symlink(input, output))
				case "hardlink output":
					output = filepath.Join(dir, "report.json")
					require.NoError(t, os.Link(input, output))
				case "symlink input":
					alias := filepath.Join(dir, "alias.yaml")
					require.NoError(t, os.Symlink(input, alias))
					paths = []string{alias}
				}
				flags.output = output
				err = runPSS(context.Background(), flags, paths)
				require.ErrorContains(t, err, "would overwrite input manifest")
				after, err := os.ReadFile(input)
				require.NoError(t, err)
				require.Equal(t, manifest, string(after), "prediction must leave the source bytes untouched")
				info, err := os.Stat(input)
				require.NoError(t, err)
				require.Equal(t, before.Mode(), info.Mode(), "report permissions must not be applied to a manifest")
				require.True(t, os.SameFile(before, info))
			})
		}
	}
}

func TestPSSProtectsManifestsReadThroughDirectoryAliases(t *testing.T) {
	dir := t.TempDir()
	sources := filepath.Join(dir, "sources")
	require.NoError(t, os.Mkdir(sources, 0o750))
	input := filepath.Join(sources, "pod.json")
	manifest := `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"app"},"spec":{"containers":[{"name":"app","image":"nginx"}]}}`
	require.NoError(t, os.WriteFile(input, []byte(manifest), 0o600))
	alias := filepath.Join(dir, "scan-root")
	require.NoError(t, os.Symlink(sources, alias))
	err := runPSS(context.Background(), &pssFlags{
		level: "Privileged", format: "json", output: input,
	}, []string{alias})
	require.ErrorContains(t, err, "would overwrite input manifest")
	after, err := os.ReadFile(input)
	require.NoError(t, err)
	require.Equal(t, manifest, string(after))
}

func TestPSSProtectsFileBackedStdin(t *testing.T) {
	for _, alias := range []bool{false, true} {
		t.Run(map[bool]string{false: "same file", true: "hardlink"}[alias], func(t *testing.T) {
			dir := t.TempDir()
			input := filepath.Join(dir, "stdin.yaml")
			require.NoError(t, os.WriteFile(input, []byte(outputSafetyManifest), 0o600))
			file, err := os.Open(input)
			require.NoError(t, err)
			defer func() { require.NoError(t, file.Close()) }()
			output := input
			if alias {
				output = filepath.Join(dir, "output.json")
				require.NoError(t, os.Link(input, output))
			}
			err = runPSS(context.Background(), &pssFlags{
				level: "Baseline", format: "json", output: output, stdin: file,
			}, []string{"-"})
			require.ErrorContains(t, err, "would overwrite input manifest")
			require.ErrorContains(t, err, "stdin")
			data, err := os.ReadFile(input)
			require.NoError(t, err)
			require.Equal(t, outputSafetyManifest, string(data))
		})
	}
}

func TestPSSSeparateReportStillWritten(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "new report", true: "existing report"}[existing], func(t *testing.T) {
			dir := t.TempDir()
			input := filepath.Join(dir, "pod.yaml")
			output := filepath.Join(t.TempDir(), "nested", "report.json")
			require.NoError(t, os.WriteFile(input, []byte(outputSafetyManifest), 0o600))
			if existing {
				require.NoError(t, os.MkdirAll(filepath.Dir(output), 0o750))
				require.NoError(t, os.WriteFile(output, []byte("previous report"), 0o600))
			}
			err := runPSS(context.Background(), &pssFlags{
				level: "Baseline", format: "json", output: output,
			}, []string{dir})
			require.ErrorContains(t, err, "PSS compliance check failed")
			report := readJSONReport(t, output)
			require.Equal(t, 1, report.Summary.Failing)
			data, err := os.ReadFile(input)
			require.NoError(t, err)
			require.Equal(t, outputSafetyManifest, string(data))
		})
	}
}

func TestPSSOutputCheckMatchesNonrecursiveInputSelection(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "pod.yaml")
	require.NoError(t, os.WriteFile(input, []byte(outputSafetyManifest), 0o600))
	// A non-manifest file in the directory is not an input. Reusing it as a
	// report is allowed, unlike an explicit path with the same extension.
	output := filepath.Join(dir, "report.txt")
	require.NoError(t, os.WriteFile(output, []byte("previous"), 0o600))
	err := runPSS(context.Background(), &pssFlags{
		level: "Privileged", format: "json", output: output,
	}, []string{dir})
	require.NoError(t, err)
	require.Equal(t, 1, readJSONReport(t, output).Summary.TotalWorkloads)

	// Directory parsing is non-recursive, so files under nested directories
	// must not be treated as source manifests either.
	nested := filepath.Join(dir, "reports")
	require.NoError(t, os.Mkdir(nested, 0o750))
	output = filepath.Join(nested, "report.json")
	require.NoError(t, os.WriteFile(output, []byte("{}"), 0o600))
	err = runPSS(context.Background(), &pssFlags{
		level: "Privileged", format: "json", output: output,
	}, []string{dir})
	require.NoError(t, err)
	require.Equal(t, 1, readJSONReport(t, output).Summary.TotalWorkloads)
}

func TestPSSNonFileStdinCanWriteExistingOutput(t *testing.T) {
	output := filepath.Join(t.TempDir(), "report.json")
	require.NoError(t, os.WriteFile(output, []byte("previous"), 0o600))
	err := runPSS(context.Background(), &pssFlags{
		level: "Privileged", format: "json", output: output,
		stdin: strings.NewReader(outputSafetyManifest),
	}, []string{"-"})
	require.NoError(t, err)
	require.Equal(t, 1, readJSONReport(t, output).Summary.TotalWorkloads)
}

func TestPSSExplicitInputIsProtectedRegardlessOfExtension(t *testing.T) {
	for _, extension := range []string{".txt", ".manifest", ""} {
		t.Run("extension="+extension, func(t *testing.T) {
			input := filepath.Join(t.TempDir(), "pod"+extension)
			require.NoError(t, os.WriteFile(input, []byte(outputSafetyManifest), 0o600))
			cwd, err := os.Getwd()
			require.NoError(t, err)
			relative, err := filepath.Rel(cwd, input)
			require.NoError(t, err)
			// The extension filter only applies to directory entries. An
			// explicitly supplied file is always parsed, even without a suffix.
			err = runPSS(context.Background(), &pssFlags{
				level: "Privileged", format: "json", output: relative,
			}, []string{input})
			require.ErrorContains(t, err, "would overwrite input manifest")
			data, err := os.ReadFile(input)
			require.NoError(t, err)
			require.Equal(t, outputSafetyManifest, string(data))
		})
	}
}

func TestPSSUnreadableStdinDoesNotTouchPreviousReport(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input.yaml")
	output := filepath.Join(dir, "report.json")
	require.NoError(t, os.WriteFile(input, []byte(outputSafetyManifest), 0o600))
	require.NoError(t, os.WriteFile(output, []byte("previous report"), 0o600))
	stdin, err := os.Open(input)
	require.NoError(t, err)
	require.NoError(t, stdin.Close())
	err = runPSS(context.Background(), &pssFlags{
		level: "Baseline", format: "json", output: output, stdin: stdin,
	}, []string{"-"})
	require.Error(t, err)
	data, err := os.ReadFile(output)
	require.NoError(t, err)
	require.Equal(t, "previous report", string(data))
}
