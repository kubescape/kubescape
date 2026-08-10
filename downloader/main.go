package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v3/core/core"
	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
)

// artifactDownloader is the slice of meta.IKubescape this command actually
// uses, so the download loop can be exercised without a live Kubescape client.
type artifactDownloader interface {
	Download(downloadInfo *metav1.DownloadInfo) (*metav1.DownloadResult, error)
}

// defaultTargets are the artifacts baked into the server image at build time.
func defaultTargets() []metav1.DownloadInfo {
	return []metav1.DownloadInfo{
		{Target: "artifacts"},                         // download all artifacts
		{Target: "framework", Identifier: "security"}, // force add the "security" framework
	}
}

// downloadAll downloads every target and reports whether any of them failed.
//
// Every target is attempted even after one fails, so a single broken artifact
// does not hide the state of the rest. The returned error is what makes the
// process exit non-zero: this binary runs as a RUN step in build/Dockerfile
// precisely so that the image build fails when artifacts cannot be fetched.
// Exiting 0 here would bake and publish a server image whose policy artifacts
// are missing.
func downloadAll(ks artifactDownloader, targets []metav1.DownloadInfo) error {
	var failed []string
	for _, target := range targets {
		// Download mutates its argument (it fills in Path/FileName), so keep
		// passing the per-iteration copy rather than the caller's slice entry.
		result, err := ks.Download(&target)
		if err != nil {
			logger.L().Error("failed to download artifact", helpers.Error(err), helpers.String("target", target.Target))
			failed = append(failed, targetID(target))
			continue
		}
		logger.L().Success("downloaded artifacts", helpers.String("count", fmt.Sprintf("%d", len(result.Files))), helpers.String("files", strings.Join(result.Files, ", ")))
	}
	if len(failed) > 0 {
		return fmt.Errorf("failed to download %d of %d artifact targets: %s", len(failed), len(targets), strings.Join(failed, ", "))
	}
	return nil
}

// targetID renders a target for the summary error, keeping the identifier so
// the two "framework" targets stay distinguishable.
func targetID(target metav1.DownloadInfo) string {
	if target.Identifier == "" {
		return target.Target
	}
	return target.Target + "/" + target.Identifier
}

func main() {
	ctx := context.Background()
	if err := downloadAll(core.NewKubescape(ctx), defaultTargets()); err != nil {
		logger.L().Fatal(err.Error())
	}
}
