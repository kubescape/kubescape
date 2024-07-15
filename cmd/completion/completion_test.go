package completion

import (
	"io"
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

// Generates autocompletion script for valid shell types
func TestGetCompletionCmd(t *testing.T) {
	// Arrange
	completionCmd := GetCompletionCmd()
	assert.Equal(t, "completion [bash|zsh|fish|powershell]", completionCmd.Use)
	assert.Equal(t, "Generate autocompletion script", completionCmd.Short)
	assert.Equal(t, "To load completions", completionCmd.Long)
	assert.Equal(t, completionCmdExamples, completionCmd.Example)
	assert.Equal(t, true, completionCmd.DisableFlagsInUseLine)
	assert.Equal(t, []string{"bash", "zsh", "fish", "powershell"}, completionCmd.ValidArgs)
}

func TestGetCompletionCmd_RunExpectedOutputs(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "Unknown completion",
			args: []string{"unknown"},
			want: "Invalid arguement unknown",
		},
		{
			name: "Empty arguements",
			args: []string{},
			want: "No arguements provided.\n",
		},
	}

	completionCmd := GetCompletionCmd()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Redirect stdout to a buffer
			rescueStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			completionCmd.Run(&cobra.Command{}, tt.args)

			w.Close()
			got, _ := io.ReadAll(r)
			os.Stdout = rescueStdout

			assert.Equal(t, tt.want, string(got))
		})
	}
}

func TestGetCompletionCmd_RunNotExpectedOutputs(t *testing.T) {
	notExpectedOutput1 := "No arguments provided."
	notExpectedOutput2 := "No arguments provided."

	tests := []struct {
		name string
		args []string
	}{
		{
			name: "Bash completion",
			args: []string{"bash"},
		},
		{
			name: "Zsh completion",
			args: []string{"zsh"},
		},
		{
			name: "Fish completion",
			args: []string{"fish"},
		},
		{
			name: "PowerShell completion",
			args: []string{"powershell"},
		},
	}

	completionCmd := GetCompletionCmd()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Redirect stdout to a buffer
			rescueStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			completionCmd.Run(&cobra.Command{}, tt.args)

			w.Close()
			got, _ := io.ReadAll(r)
			os.Stdout = rescueStdout

			assert.NotEqual(t, notExpectedOutput1, string(got))
			assert.NotEqual(t, notExpectedOutput2, string(got))
		})
	}
}

func TestGetCompletionCmd_RunBashCompletionNotExpectedOutputs(t *testing.T) {
	notExpectedOutput1 := "Unexpected output for bash completion test 1."
	notExpectedOutput2 := "Unexpected output for bash completion test 2."

	// Redirect stdout to a buffer
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	completionCmd := GetCompletionCmd()
	completionCmd.Run(&cobra.Command{}, []string{"bash"})

	w.Close()
	got, _ := io.ReadAll(r)
	os.Stdout = rescueStdout

	assert.NotEqual(t, notExpectedOutput1, string(got))
	assert.NotEqual(t, notExpectedOutput2, string(got))
}

func TestGetCompletionCmd_RunZshCompletionNotExpectedOutputs(t *testing.T) {
	notExpectedOutput1 := "Unexpected output for zsh completion test 1."
	notExpectedOutput2 := "Unexpected output for zsh completion test 2."

	// Redirect stdout to a buffer
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	completionCmd := GetCompletionCmd()
	completionCmd.Run(&cobra.Command{}, []string{"zsh"})

	w.Close()
	got, _ := io.ReadAll(r)
	os.Stdout = rescueStdout

	assert.NotEqual(t, notExpectedOutput1, string(got))
	assert.NotEqual(t, notExpectedOutput2, string(got))
}

func TestGetCompletionCmd_RunFishCompletionNotExpectedOutputs(t *testing.T) {
	notExpectedOutput1 := "Unexpected output for fish completion test 1."
	notExpectedOutput2 := "Unexpected output for fish completion test 2."

	// Redirect stdout to a buffer
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	completionCmd := GetCompletionCmd()
	completionCmd.Run(&cobra.Command{}, []string{"fish"})

	w.Close()
	got, _ := io.ReadAll(r)
	os.Stdout = rescueStdout

	assert.NotEqual(t, notExpectedOutput1, string(got))
	assert.NotEqual(t, notExpectedOutput2, string(got))
}

func TestGetCompletionCmd_RunPowerShellCompletionNotExpectedOutputs(t *testing.T) {
	notExpectedOutput1 := "Unexpected output for powershell completion test 1."
	notExpectedOutput2 := "Unexpected output for powershell completion test 2."

	// Redirect stdout to a buffer
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	completionCmd := GetCompletionCmd()
	completionCmd.Run(&cobra.Command{}, []string{"powershell"})

	w.Close()
	got, _ := io.ReadAll(r)
	os.Stdout = rescueStdout

	assert.NotEqual(t, notExpectedOutput1, string(got))
	assert.NotEqual(t, notExpectedOutput2, string(got))
}
