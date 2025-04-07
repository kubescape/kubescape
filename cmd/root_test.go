package cmd

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewDefaultKubescapeCommand(t *testing.T) {
	t.Run("NewDefaultKubescapeCommand", func(t *testing.T) {
		cmd := NewDefaultKubescapeCommand(context.Background())
		assert.NotNil(t, cmd)
	})
}

func TestExecute(t *testing.T) {
	t.Run("Execute", func(t *testing.T) {
		err := Execute(context.Background())
		if err != nil {
			assert.EqualErrorf(t, err, "unknown command \"^\\\\QTestExecute\\\\E$\" for \"kubescape\"", err.Error())
		}
	})
}
