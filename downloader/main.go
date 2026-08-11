package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v3/core/core"
	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
)

type Downloader interface {
	Download(downloadInfo *metav1.DownloadInfo) (*metav1.DownloadResult, error)
}

func downloadArtifacts(ks Downloader, downloads []metav1.DownloadInfo) error {
	var errs []error
	for _, download := range downloads {
		result, err := ks.Download(&download)
		if err != nil {
			logger.L().Error("failed to download artifact", helpers.Error(err), helpers.String("target", download.Target))
			errs = append(errs, err)
			continue
		}
		logger.L().Success("downloaded artifacts", helpers.String("count", fmt.Sprintf("%d", len(result.Files))), helpers.String("files", strings.Join(result.Files, ", ")))
	}
	return errors.Join(errs...)
}

func main() {
	ctx := context.Background()
	ks := core.NewKubescape(ctx)
	downloads := []metav1.DownloadInfo{
		{Target: "artifacts"},                         // download all artifacts
		{Target: "framework", Identifier: "security"}, // force add the "security" framework
	}
	if err := downloadArtifacts(ks, downloads); err != nil {
		logger.L().Error("failed to download all artifacts", helpers.Error(err))
		os.Exit(1)
	}
}
