package ghworkflows

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kubescape/kubescape/v4/internal/testutils"
)

func TestInstallScriptWindowsUpgradeSafety(t *testing.T) {
	powershell, err := exec.LookPath("powershell.exe")
	if err != nil {
		t.Skip("Windows PowerShell is required")
	}

	repoRoot := filepath.Clean(filepath.Join(testutils.CurrentDir(), "..", ".."))
	source, err := os.ReadFile(filepath.Join(repoRoot, "install.ps1"))
	if err != nil {
		t.Fatal(err)
	}

	// Stop after installation so the test does not execute the fake binary.
	marker := "# Update user PATH if needed"
	markerIndex := strings.Index(string(source), marker)
	if markerIndex < 0 {
		t.Fatal("could not find installation completion marker")
	}
	installerSource := string(source[:markerIndex])

	hash := sha256.Sum256([]byte("new-download"))
	validHash := hex.EncodeToString(hash[:])

	tests := []struct {
		name        string
		mode        string
		existing    bool
		wantExit    int
		wantExists  bool
		wantContent string
	}{
		{
			name:        "manifest download failure preserves existing executable",
			mode:        "manifest-failure",
			existing:    true,
			wantExit:    1,
			wantExists:  true,
			wantContent: "old-binary",
		},
		{
			name:        "checksum mismatch preserves existing executable",
			mode:        "checksum-mismatch",
			existing:    true,
			wantExit:    1,
			wantExists:  true,
			wantContent: "old-binary",
		},
		{
			name:        "missing checksum entry preserves existing executable",
			mode:        "missing-entry",
			existing:    true,
			wantExit:    1,
			wantExists:  true,
			wantContent: "old-binary",
		},
		{
			name:        "successful upgrade replaces existing executable",
			mode:        "success",
			existing:    true,
			wantExit:    0,
			wantExists:  true,
			wantContent: "new-download",
		},
		{
			name:        "replacement failure restores existing executable",
			mode:        "replace-failure",
			existing:    true,
			wantExit:    1,
			wantExists:  true,
			wantContent: "old-binary",
		},
		{
			name:        "first installation succeeds",
			mode:        "success",
			existing:    false,
			wantExit:    0,
			wantExists:  true,
			wantContent: "new-download",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			homeDir := filepath.Join(tempDir, "home")
			installDir := filepath.Join(homeDir, ".kubescape")
			outputPath := filepath.Join(installDir, "kubescape.exe")

			if err := os.MkdirAll(homeDir, 0700); err != nil {
				t.Fatal(err)
			}

			if tt.existing {
				if err := os.MkdirAll(installDir, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(outputPath, []byte("old-binary"), 0600); err != nil {
					t.Fatal(err)
				}
			}

			var manifestBlock string

			switch tt.mode {
			case "manifest-failure":
				manifestBlock = `throw "Simulated checksum manifest failure"`

			case "checksum-mismatch":
				manifestBlock = fmt.Sprintf(
					`$content = "%s  " + $script:asset + [Environment]::NewLine
return [PSCustomObject]@{ Content = $content }`,
					strings.Repeat("0", 64),
				)

			case "missing-entry":
				manifestBlock = fmt.Sprintf(
					`$content = "%s  another-asset.exe" + [Environment]::NewLine
return [PSCustomObject]@{ Content = $content }`,
					validHash,
				)

			case "success", "replace-failure":
				manifestBlock = fmt.Sprintf(
					`$content = "%s  " + $script:asset + [Environment]::NewLine
return [PSCustomObject]@{ Content = $content }`,
					validHash,
				)
			}

			mockFunctions := fmt.Sprintf(`
function Start-BitsTransfer {
    param([string]$Source, [string]$Destination)
    [System.IO.File]::WriteAllText($Destination, "new-download")
}

function Invoke-WebRequest {
    param([string]$Uri, [string]$OutFile, [switch]$UseBasicParsing)

    if ($Uri -like "*/checksums.sha256") {
        %s
    }

    if ($OutFile) {
        [System.IO.File]::WriteAllText($OutFile, "new-download")
        return
    }

    throw "Unexpected request: $Uri"
}
`, manifestBlock)

			testInstallerSource := installerSource

			if tt.mode == "replace-failure" {
				original := "[System.IO.File]::Replace($downloadPath, $outputPath, $backupPath)"

				simulatedFailure := `[System.IO.File]::Move($outputPath, $backupPath)
throw "Simulated replacement failure after moving existing executable"`

				if !strings.Contains(testInstallerSource, original) {
					t.Fatal("could not find executable replacement operation")
				}

				testInstallerSource = strings.Replace(
					testInstallerSource,
					original,
					simulatedFailure,
					1,
				)
			}

			testScript := filepath.Join(tempDir, "install-test.ps1")
			script := mockFunctions + "\n" + testInstallerSource + "\nexit 0\n"
			if err := os.WriteFile(testScript, []byte(script), 0600); err != nil {
				t.Fatal(err)
			}

			cmd := exec.Command(
				powershell,
				"-NoProfile",
				"-NonInteractive",
				"-ExecutionPolicy", "Bypass",
				"-File", testScript,
				"-v", "v-test",
				"-n",
			)

			cmd.Env = replaceEnvValueForInstallTest(
				os.Environ(),
				"USERPROFILE",
				homeDir,
			)

			output, runErr := cmd.CombinedOutput()
			if tt.mode == "replace-failure" &&
				!strings.Contains(string(output), "Restored the previous kubescape executable.") {
				t.Errorf("expected previous executable to be restored, got:\n%s", output)
			}

			if tt.wantExit == 0 {
				if runErr != nil {
					t.Fatalf("installer failed: %v\n%s", runErr, output)
				}
			} else {
				exitErr, ok := runErr.(*exec.ExitError)
				if !ok || exitErr.ExitCode() != tt.wantExit {
					t.Fatalf("expected exit code %d, got %v\n%s",
						tt.wantExit, runErr, output)
				}
			}

			content, readErr := os.ReadFile(outputPath)

			if tt.wantExists {
				if readErr != nil {
					t.Fatalf("expected executable to exist: %v", readErr)
				}
				if string(content) != tt.wantContent {
					t.Errorf("expected content %q, got %q",
						tt.wantContent, string(content))
				}
			} else if !os.IsNotExist(readErr) {
				t.Errorf("expected executable not to exist, got %v", readErr)
			}

			tempFiles, err := filepath.Glob(
				filepath.Join(installDir, "kubescape.exe.*.tmp"),
			)
			if err != nil {
				t.Fatal(err)
			}
			if len(tempFiles) != 0 {
				t.Errorf("temporary download files were not cleaned up: %v", tempFiles)
			}
		})
	}
}
