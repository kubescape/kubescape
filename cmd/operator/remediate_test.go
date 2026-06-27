package operator

import (
	"testing"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/mocks"
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
	assert.Nil(t, cmd.Args(&cobra.Command{}, []string{revertSubCommand}))

	// unknown action is rejected
	err = cmd.Args(&cobra.Command{}, []string{"quarantine"})
	assert.Error(t, err)

	// expected flags are registered
	for _, name := range []string{"namespace", "kind", "target-namespace", "name", "reason", "finding-ref", "dry-run", "confirm"} {
		assert.NotNil(t, cmd.PersistentFlags().Lookup(name), "flag --%s should be registered", name)
	}

	// dry-run defaults to true
	dryRun, err := cmd.PersistentFlags().GetBool("dry-run")
	assert.NoError(t, err)
	assert.True(t, dryRun)
}
