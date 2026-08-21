package policy

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicyTestCmd_PassingRuleReturnsNoError(t *testing.T) {
	dir, err := filepath.Abs("../../rules/modify-node-status-v1")
	require.NoError(t, err)

	cmd := getPolicyTestCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{dir})

	err = cmd.Execute()
	require.NoError(t, err)
	assert.Contains(t, out.String(), "cases passed")
}

func TestPolicyTestCmd_MissingPathReturnsError(t *testing.T) {
	cmd := getPolicyTestCmd()
	cmd.SetArgs([]string{"/nonexistent/path/for/policy/test"})
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true

	err := cmd.Execute()
	assert.Error(t, err)
}
