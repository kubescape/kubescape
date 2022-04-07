package cautils

import (
	"testing"

	reporthandlingv2 "github.com/armosec/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
)

// func TestSetInputPatterns(t *testing.T) { //Unitest
// 	{
// 		scanInfo := ScanInfo{
// 			InputPatterns: []string{"file"},
// 		}
// 		scanInfo.setInputPatterns()
// 		assert.Equal(t, "file", scanInfo.InputPatterns[0])
// 	}
// }

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
	}
	{
		ctx := reporthandlingv2.ContextMetadata{}
		setContextMetadata(&ctx, "scaninfo_test.go")

		assert.Nil(t, ctx.ClusterContextMetadata)
		assert.Nil(t, ctx.DirectoryContextMetadata)
		assert.NotNil(t, ctx.FileContextMetadata)
		assert.Nil(t, ctx.HelmContextMetadata)
		assert.Nil(t, ctx.RepoContextMetadata)
	}
	{
		ctx := reporthandlingv2.ContextMetadata{}
		setContextMetadata(&ctx, "https://github.com/armosec/kubescape")

		assert.Nil(t, ctx.ClusterContextMetadata)
		assert.Nil(t, ctx.DirectoryContextMetadata)
		assert.Nil(t, ctx.FileContextMetadata)
		assert.Nil(t, ctx.HelmContextMetadata)
		assert.Nil(t, ctx.RepoContextMetadata) // TODO
	}
}

func TestGetHostname(t *testing.T) {
	assert.NotEqual(t, "", getHostname())
}
