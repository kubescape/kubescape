package completion

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestCompletionUsesCommandWriter(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		t.Run(shell, func(t *testing.T) {
			var output bytes.Buffer
			root := &cobra.Command{Use: "kubescape"}
			root.AddCommand(GetCompletionCmd())
			root.SetOut(&output)
			root.SetErr(io.Discard)
			root.SetArgs([]string{"completion", shell})

			if err := root.Execute(); err != nil {
				t.Fatalf("generate %s completion: %v", shell, err)
			}
			if !strings.Contains(output.String(), "kubescape") {
				t.Fatalf("expected a completion script in the configured writer, got %q", output.String())
			}
		})
	}
}

type failingCompletionWriter struct {
	err error
}

func (w failingCompletionWriter) Write([]byte) (int, error) {
	return 0, w.err
}

func TestCompletionReturnsWriteError(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		t.Run(shell, func(t *testing.T) {
			writeErr := errors.New("completion output unavailable")
			root := &cobra.Command{Use: "kubescape"}
			root.AddCommand(GetCompletionCmd())
			root.SetOut(failingCompletionWriter{err: writeErr})
			root.SetErr(io.Discard)
			root.SetArgs([]string{"completion", shell})

			if err := root.Execute(); !errors.Is(err, writeErr) {
				t.Fatalf("expected writer error %v, got %v", writeErr, err)
			}
		})
	}
}

func TestCompletionRejectsInvalidArguments(t *testing.T) {
	for _, args := range [][]string{nil, {"unknown"}, {"bash", "zsh"}} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			var output bytes.Buffer
			root := &cobra.Command{Use: "kubescape", SilenceUsage: true}
			root.AddCommand(GetCompletionCmd())
			root.SetOut(&output)
			root.SetErr(io.Discard)
			root.SetArgs(append([]string{"completion"}, args...))
			if err := root.Execute(); err == nil {
				t.Fatal("expected argument validation error")
			}
			if output.Len() != 0 {
				t.Fatalf("invalid arguments generated output: %q", output.String())
			}
		})
	}
}

func TestCompletionHelpExamples(t *testing.T) {
	var output bytes.Buffer

	root := &cobra.Command{Use: "kubescape"}
	root.AddCommand(GetCompletionCmd())
	root.SetOut(&output)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"completion", "--help"})

	if err := root.Execute(); err != nil {
		t.Fatalf("show completion help: %v", err)
	}

	help := output.String()

	expectedExamples := []string{
		"Generate completion scripts for Bash, Zsh, Fish, and PowerShell.",
		"echo 'source <(kubescape completion bash)' >> ~/.bashrc",
		`completion zsh > "${fpath[1]}/_`,
		"completion fish > ~/.config/fish/completions/",
		"completion powershell >> $PROFILE",
	}

	for _, example := range expectedExamples {
		if !strings.Contains(help, example) {
			t.Errorf("completion help is missing expected example %q", example)
		}
	}

	brokenZshExample := `completion zsh)' >> "${fpath[1]}/_`

	if strings.Contains(help, brokenZshExample) {
		t.Error("completion help still contains the incorrect persistent Zsh instruction")
	}
}
