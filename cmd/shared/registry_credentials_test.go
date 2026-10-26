package shared

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegistryCredentialConstants(t *testing.T) {
	assert.Equal(t, "KUBESCAPE_REGISTRY_USERNAME", RegistryUsernameEnvVar)
	assert.Equal(t, "KUBESCAPE_REGISTRY_PASSWORD", RegistryPasswordEnvVar)
	assert.Equal(t, "KUBESCAPE_REGISTRY_TOKEN", RegistryTokenEnvVar)
}

func TestRegistryCredentialFlagChanged(t *testing.T) {
	t.Run("nil command returns false", func(t *testing.T) {
		assert.False(t, RegistryCredentialFlagChanged(nil, "username", "password"))
	})

	t.Run("no names specified returns false", func(t *testing.T) {
		cmd := &cobra.Command{Use: "test"}
		cmd.Flags().String("username", "", "")
		assert.False(t, RegistryCredentialFlagChanged(cmd))
	})

	t.Run("unregistered flag returns false", func(t *testing.T) {
		cmd := &cobra.Command{Use: "test"}
		assert.False(t, RegistryCredentialFlagChanged(cmd, "unregistered"))
	})

	t.Run("local flag unchanged returns false", func(t *testing.T) {
		cmd := &cobra.Command{Use: "test"}
		cmd.Flags().String("username", "", "")
		assert.False(t, RegistryCredentialFlagChanged(cmd, "username"))
	})

	t.Run("local flag changed returns true", func(t *testing.T) {
		cmd := &cobra.Command{Use: "test"}
		cmd.Flags().String("username", "", "")
		require.NoError(t, cmd.Flags().Set("username", "testuser"))
		assert.True(t, RegistryCredentialFlagChanged(cmd, "username"))
	})

	t.Run("local flag explicitly set to empty string returns true", func(t *testing.T) {
		cmd := &cobra.Command{Use: "test"}
		cmd.Flags().String("username", "", "")
		require.NoError(t, cmd.Flags().Set("username", ""))
		assert.True(t, RegistryCredentialFlagChanged(cmd, "username"),
			"explicitly empty flag must count as changed to prevent falling back to ambient env vars")
	})

	t.Run("persistent flag unchanged returns false", func(t *testing.T) {
		cmd := &cobra.Command{Use: "test"}
		cmd.PersistentFlags().String("password", "", "")
		assert.False(t, RegistryCredentialFlagChanged(cmd, "password"))
	})

	t.Run("persistent flag changed returns true", func(t *testing.T) {
		cmd := &cobra.Command{Use: "test"}
		cmd.PersistentFlags().String("password", "", "")
		require.NoError(t, cmd.PersistentFlags().Set("password", "secret"))
		assert.True(t, RegistryCredentialFlagChanged(cmd, "password"))
	})

	t.Run("persistent flag explicitly set to empty string returns true", func(t *testing.T) {
		cmd := &cobra.Command{Use: "test"}
		cmd.PersistentFlags().String("password", "", "")
		require.NoError(t, cmd.PersistentFlags().Set("password", ""))
		assert.True(t, RegistryCredentialFlagChanged(cmd, "password"))
	})

	t.Run("inherited flag from parent command returns true when changed", func(t *testing.T) {
		parent := &cobra.Command{Use: "root"}
		parent.PersistentFlags().String("token", "", "")
		child := &cobra.Command{Use: "sub"}
		parent.AddCommand(child)

		// Before setting flag on parent
		assert.False(t, RegistryCredentialFlagChanged(child, "token"))

		// When set on parent, child command inherits it through InheritedFlags
		require.NoError(t, parent.PersistentFlags().Set("token", "mytoken"))
		assert.True(t, RegistryCredentialFlagChanged(child, "token"))
	})

	t.Run("multiple names where none changed returns false", func(t *testing.T) {
		cmd := &cobra.Command{Use: "test"}
		cmd.Flags().String("registry-username", "", "")
		cmd.Flags().String("username", "", "")
		assert.False(t, RegistryCredentialFlagChanged(cmd, "registry-username", "username"))
	})

	t.Run("multiple names where first changed returns true", func(t *testing.T) {
		cmd := &cobra.Command{Use: "test"}
		cmd.Flags().String("registry-username", "", "")
		cmd.Flags().String("username", "", "")
		require.NoError(t, cmd.Flags().Set("registry-username", "user1"))
		assert.True(t, RegistryCredentialFlagChanged(cmd, "registry-username", "username"))
	})

	t.Run("multiple names where second changed returns true", func(t *testing.T) {
		cmd := &cobra.Command{Use: "test"}
		cmd.Flags().String("registry-username", "", "")
		cmd.Flags().String("username", "", "")
		require.NoError(t, cmd.Flags().Set("username", "user2"))
		assert.True(t, RegistryCredentialFlagChanged(cmd, "registry-username", "username"))
	})

	t.Run("multiple names where some do not exist returns true if registered flag changed", func(t *testing.T) {
		cmd := &cobra.Command{Use: "test"}
		cmd.Flags().String("username", "", "")
		require.NoError(t, cmd.Flags().Set("username", "user3"))
		assert.True(t, RegistryCredentialFlagChanged(cmd, "nonexistent", "username"))
	})
}
