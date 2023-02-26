package main

import (
	"context"
	"net/url"
	"os"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/kubescape/v2/core/cautils"
	_ "github.com/kubescape/kubescape/v2/httphandler/docs"
	"github.com/kubescape/kubescape/v2/httphandler/listener"
)

func main() {
	ctx := context.Background()
	// to enable otel, set OTEL_COLLECTOR_SVC=otel-collector:4317
	if otelHost, present := os.LookupEnv("OTEL_COLLECTOR_SVC"); present {
		ctx = logger.InitOtel("kubescape",
			os.Getenv(cautils.BuildNumber),
			os.Getenv("ACCOUNT_ID"),
			os.Getenv("CLUSTER_NAME"),
			url.URL{Host: otelHost})
		defer logger.ShutdownOtel(ctx)
	}

	// traces will be created by otelmux.Middleware in SetupHTTPListener()

	logger.L().Ctx(ctx).Fatal(listener.SetupHTTPListener().Error())
}
