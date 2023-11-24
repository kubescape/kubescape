package completion

import (
	"testing"

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
