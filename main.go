package main

import (
	"context"
	"net/url"
	"os"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/kubescape/v2/cmd"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"go.opentelemetry.io/otel"
)

func main() {
	ctx := context.Background()
	// to enable otel, set OTEL_COLLECTOR_SVC=otel-collector:4317
	if otelHost, present := os.LookupEnv("OTEL_COLLECTOR_SVC"); present {
		ctx = logger.InitOtel("kubescape",
			os.Getenv(cautils.BuildNumber),
			os.Getenv("ACCOUNT_ID"),
			url.URL{Host: otelHost})
		defer logger.ShutdownOtel(ctx)
	}

	ctx, span := otel.Tracer("").Start(ctx, "kubescape-cli")
	defer span.End()

	if err := cmd.Execute(ctx); err != nil {
		logger.L().Ctx(ctx).Fatal(err.Error())
	}
}
