package operator

import (
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/mocks"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestGetOperatorRemediateCmd(t *testing.T) {
	cmd := getOperatorRemediateCmd(&mocks.MockIKubescape{}, cautils.OperatorInfo{})

	assert.Equal(t, "remediate <action>", cmd.Use)

	// no action -> error
	err := cmd.Args(&cobra.Command{}, []string{})
	assert.Error(t, err)

	// supported actions pass arg validation
	assert.Nil(t, cmd.Args(&cobra.Command{}, []string{annotateSubCommand}))
	assert.Nil(t, cmd.Args(&cobra.Command{}, []string{quarantineSubCommand}))
	assert.Nil(t, cmd.Args(&cobra.Command{}, []string{revertSubCommand}))

	// unknown action is rejected
	err = cmd.Args(&cobra.Command{}, []string{"explode"})
	assert.Error(t, err)

	// exactly one action is required: extra positional args are rejected
	err = cmd.Args(&cobra.Command{}, []string{annotateSubCommand, "unexpected"})
	assert.Error(t, err)

	// expected flags are registered
	for _, name := range []string{"namespace", "kind", "target-namespace", "name", "control", "min-severity", "reason", "finding-ref", "confirm"} {
		assert.NotNil(t, cmd.PersistentFlags().Lookup(name), "flag --%s should be registered", name)
	}

	// the findings-driven flags default to empty, so a plain invocation is never
	// silently a cluster-wide selector run
	for _, name := range []string{"control", "min-severity"} {
		value, err := cmd.PersistentFlags().GetString(name)
		assert.NoError(t, err)
		assert.Empty(t, value, "flag --%s should default to empty", name)
	}

	// confirm defaults to false (dry-run is the default; --confirm is the only apply switch)
	confirm, err := cmd.PersistentFlags().GetBool("confirm")
	assert.NoError(t, err)
	assert.False(t, confirm)
}
