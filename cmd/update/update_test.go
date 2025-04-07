package update

import (
	"context"
	"testing"

	"github.com/kubescape/kubescape/v3/core/core"
	"github.com/stretchr/testify/assert"
)

func TestGetUpdateCmd(t *testing.T) {
	ks := core.NewKubescape(context.TODO())
	cmd := GetUpdateCmd(ks)
	assert.NotNil(t, cmd)

	err := cmd.RunE(cmd, []string{})
	assert.Nil(t, err)
}
