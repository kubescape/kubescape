package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v3/core/core"
	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
)

func main() {
	ctx := context.Background()
	ks := core.NewKubescape(ctx)
	downloads := []metav1.DownloadInfo{
		{Target: "artifacts"},                         // download all artifacts
		{Target: "framework", Identifier: "security"}, // force add the "security" framework
	}
	var hasError bool
	for _, download := range downloads {
		result, err := ks.Download(&download)
		if err != nil {
			logger.L().Error("failed to download artifact", helpers.Error(err), helpers.String("target", download.Target))
			hasError = true
			continue
		}
		logger.L().Success("downloaded artifacts", helpers.String("count", fmt.Sprintf("%d", len(result.Files))), helpers.String("files", strings.Join(result.Files, ", ")))
	}

	if hasError {
		os.Exit(1)
	}
}
