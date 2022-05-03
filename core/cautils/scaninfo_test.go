package cautils

import (
	"testing"

	reporthandlingv2 "github.com/armosec/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
)

func TestSetContextMetadata(t *testing.T) {
	{
		ctx := reporthandlingv2.ContextMetadata{}
		setContextMetadata(&ctx, "")

		assert.NotNil(t, ctx.ClusterContextMetadata)
		assert.Nil(t, ctx.DirectoryContextMetadata)
		assert.Nil(t, ctx.FileContextMetadata)
		assert.Nil(t, ctx.HelmContextMetadata)
		assert.Nil(t, ctx.RepoContextMetadata)
	}
	{
		ctx := reporthandlingv2.ContextMetadata{}
		setContextMetadata(&ctx, "file")

		assert.Nil(t, ctx.ClusterContextMetadata)
		assert.NotNil(t, ctx.DirectoryContextMetadata)
		assert.Nil(t, ctx.FileContextMetadata)
		assert.Nil(t, ctx.HelmContextMetadata)
		assert.Nil(t, ctx.RepoContextMetadata)

		hostName := getHostname()
		assert.Contains(t, ctx.DirectoryContextMetadata.BasePath, "file")
		assert.Equal(t, hostName, ctx.DirectoryContextMetadata.HostName)
	}
	{
		ctx := reporthandlingv2.ContextMetadata{}
		setContextMetadata(&ctx, "scaninfo_test.go")

		assert.Nil(t, ctx.ClusterContextMetadata)
		assert.Nil(t, ctx.DirectoryContextMetadata)
		assert.NotNil(t, ctx.FileContextMetadata)
		assert.Nil(t, ctx.HelmContextMetadata)
		assert.Nil(t, ctx.RepoContextMetadata)

		hostName := getHostname()
		assert.Contains(t, ctx.FileContextMetadata.FilePath, "scaninfo_test.go")
		assert.Equal(t, hostName, ctx.FileContextMetadata.HostName)
	}
	{
		ctx := reporthandlingv2.ContextMetadata{}
		setContextMetadata(&ctx, "https://github.com/armosec/kubescape")

		assert.Nil(t, ctx.ClusterContextMetadata)
		assert.Nil(t, ctx.DirectoryContextMetadata)
		assert.Nil(t, ctx.FileContextMetadata)
		assert.Nil(t, ctx.HelmContextMetadata)
		assert.NotNil(t, ctx.RepoContextMetadata)

		assert.Equal(t, "kubescape", ctx.RepoContextMetadata.Repo)
		assert.Equal(t, "armosec", ctx.RepoContextMetadata.Owner)
		assert.Equal(t, "master", ctx.RepoContextMetadata.Branch)
	}
}

func TestGetHostname(t *testing.T) {
	assert.NotEqual(t, "", getHostname())
}
