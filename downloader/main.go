package main

import (
	"context"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v3/core/core"
	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
)

func main() {
	ctx := context.TODO()
	ks := core.NewKubescape(ctx)
	downloads := []metav1.DownloadInfo{
		{Target: "artifacts"},                         // download all artifacts
		{Target: "framework", Identifier: "security"}, // force add the "security" framework
	}
	for _, download := range downloads {
		if err := ks.Download(&download); err != nil {
			logger.L().Error("failed to download artifact", helpers.Error(err), helpers.String("target", download.Target))
		}
	}
}
