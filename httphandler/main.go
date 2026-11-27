package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	v1 "github.com/kubescape/backend/pkg/client/v1"
	"github.com/kubescape/backend/pkg/servicediscovery"
	"github.com/kubescape/backend/pkg/servicediscovery/schema"
	servicediscoveryv3 "github.com/kubescape/backend/pkg/servicediscovery/v3"
	"github.com/kubescape/backend/pkg/utils"
	"github.com/kubescape/backend/pkg/versioncheck"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/go-logger/zaplogger"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	"github.com/kubescape/kubescape/v4/core/pkg/filesizelimit"
	"github.com/kubescape/kubescape/v4/httphandler/config"
	_ "github.com/kubescape/kubescape/v4/httphandler/docs"
	"github.com/kubescape/kubescape/v4/httphandler/listener"
	"github.com/kubescape/kubescape/v4/httphandler/storage"
	"github.com/kubescape/kubescape/v4/pkg/ksinit"
)

// GoReleaser will fill these at build time
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

const (
	defaultNamespace = "kubescape"
)

var serviceDiscoveryTimeout = 10 * time.Second

func main() {
	if err := runWithSignals(run); err != nil {
		logger.L().Error("Kubescape server stopped", helpers.Error(err))
		os.Exit(1)
	}
}

// Keep signal registration and deferred application cleanup inside the runner,
// so even an error exit from main happens after cleanup has completed.
func runWithSignals(serve func(context.Context) error) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return serve(ctx)
}

func run(ctx context.Context) error {
	versioncheck.BuildNumber = version

	logger.L().Info("Starting Kubescape server",
		helpers.String("version", version),
		helpers.String("commit", commit),
		helpers.String("date", date))

	if err := config.ConfigureNamespaceFilters(os.Getenv(config.NamespaceFiltersFileEnv)); err != nil {
		return err
	}

	cfg, err := config.LoadConfig("/etc/config")
	if err != nil {
		logger.L().Ctx(ctx).Error("load config error", helpers.Error(err))
	}

	loadAndSetCredentials()

	clusterName := getClusterName(cfg)

	// to enable otel, set OTEL_COLLECTOR_SVC=otel-collector:4317
	if otelHost, present := os.LookupEnv("OTEL_COLLECTOR_SVC"); present {
		logger.InitOtel("kubescape",
			version,
			config.GetAccount(),
			clusterName,
			url.URL{Host: otelHost})
		defer flushOtel(ctx, logger.ShutdownOtel)
	}

	logger.L().Debug("setting cluster context name", helpers.String("context", os.Getenv("KS_CONTEXT")))
	k8sinterface.SetClusterContextName(os.Getenv("KS_CONTEXT"))

	initializeLoggerName()
	initializeLoggerLevel()
	initializeSaaSEnv()
	initializeStorage(clusterName, cfg)
	// traces will be created by otelmux.Middleware in SetupHTTPListener()

	auth, err := listener.NewAPIAuth(ctx)
	if err != nil {
		logger.L().Fatal("API auth initialization error", helpers.Error(err))
		return err
	}

	return listener.SetupHTTPListener(ctx, auth)
}

func flushOtel(ctx context.Context, shutdown func(context.Context)) {
	flushCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	shutdown(flushCtx)
}

func initializeStorage(clusterName string, cfg config.Config) {
	namespace := getNamespace(cfg)
	logger.L().Debug("initializing storage", helpers.String("namespace", namespace))

	// Use shared ksinit logic for storage connection
	ksClient, err := ksinit.CreateKsObjectConnection(namespace, 0)
	if err != nil {
		logger.L().Fatal("storage initialization error", helpers.Error(err))
		return
	}

	s, err := storage.NewAPIServerStorage(clusterName, namespace, ksClient, cfg.ContinuousPostureScan)
	if err != nil {
		logger.L().Fatal("storage initialization error", helpers.Error(err))
		return
	}
	storage.SetStorage(s)
}

// initialize logger name
func initializeLoggerName() {
	loggerName := zaplogger.LoggerName
	if l := os.Getenv("KS_LOGGER_NAME"); l != "" {
		loggerName = l
	}
	logger.InitLogger(loggerName)
}

// initialize logger level
func initializeLoggerLevel() {
	loggerLevel := helpers.DebugLevel.String()
	if l := os.Getenv("KS_LOGGER_LEVEL"); l != "" {
		loggerLevel = l
	}
	if err := logger.L().SetLevel(loggerLevel); err != nil {
		logger.L().SetLevel(helpers.DebugLevel.String())
		logger.L().Error("failed to set logger level", helpers.String("level", loggerLevel), helpers.Error(err), helpers.String("default", helpers.DebugLevel.String()))
	}
}

// defaultServiceDiscoveryPath is a package-level indirection so tests can
// override the fallback path without depending on /etc/config/services.json
// being absent on the machine running the tests.
var defaultServiceDiscoveryPath = "/etc/config/services.json"

func initializeSaaSEnv() {
	var sdGetter schema.IServiceDiscoveryServiceGetter

	// Prefer file-based discovery: allows sidecar and private-cluster deployments
	// to inject endpoints without network egress to api.armosec.io.
	// A present-but-empty value (common for an unset Helm value) is treated
	// the same as absent, not as an explicit override.
	envPath, hasExplicitPath := os.LookupEnv("KS_SERVICE_DISCOVERY_FILE_PATH")
	hasExplicitPath = hasExplicitPath && envPath != ""
	path := defaultServiceDiscoveryPath
	if hasExplicitPath {
		path = envPath
	}
	data, fileDiscoveryErr := readBoundedRegularFile(path, filesizelimit.GetMaxFileSize(), errServiceDiscoveryNotRegular, errServiceDiscoveryTooLarge)
	if fileDiscoveryErr != nil {
		if !errors.Is(fileDiscoveryErr, os.ErrNotExist) {
			logger.L().Warning("invalid service-discovery file - skipping SaaS wiring", helpers.String("path", path), helpers.Error(fileDiscoveryErr))
			return
		}
		// An explicit file path was configured but isn't there (typo, or a
		// configmap that hasn't finished mounting yet) - this is a
		// configuration problem, not "no backend configured", and falling
		// back to the public SaaS endpoint would be a surprising thing to
		// do silently for a deployer who opted into file-based discovery.
		if hasExplicitPath {
			logger.L().Warning("configured service-discovery file not found - skipping SaaS wiring", helpers.String("path", path), helpers.Error(fileDiscoveryErr))
			return
		}

		// No backend was configured (no server URL and no account/access key) -
		// do not reach out to the default public SaaS endpoint.
		if os.Getenv("API_URL") == "" && config.GetAccount() == "" && config.GetAccessKey() == "" {
			logger.L().Info("no backend configured (server/account/accessKey not set) - skipping SaaS wiring")
			return
		}
	}

	if fileDiscoveryErr == nil {
		logger.L().Info("using file-based service discovery", helpers.String("path", path))
		sdGetter = servicediscoveryv3.NewServiceDiscoveryStreamV3(data)
	} else {
		apiURL := "api.armosec.io"
		if envVar := os.Getenv("API_URL"); envVar != "" {
			logger.L().Debug("API URL updated from env var", helpers.String("url", envVar))
			apiURL = envVar
		}
		client, err := servicediscoveryv3.NewServiceDiscoveryClientV3(apiURL)
		if err != nil {
			logger.L().Fatal("failed to initialize service discovery client", helpers.Error(err))
			return
		}
		sdGetter = client
	}

	backendServices, err := getServicesWithTimeout(sdGetter, serviceDiscoveryTimeout)
	if err != nil {
		logger.L().Warning("failed to get backend services - skipping SaaS wiring", helpers.Error(err))
		return
	}

	if ksCloud, err := v1.NewKSCloudAPI(backendServices.GetApiServerUrl(), backendServices.GetReportReceiverHttpUrl(), config.GetAccount(), config.GetAccessKey()); err != nil {
		logger.L().Fatal("failed to initialize cloud api", helpers.Error(err))
	} else {
		getter.SetKSCloudAPIConnector(ksCloud)
	}
}

// getServicesWithTimeout runs servicediscovery.GetServices in a goroutine and returns
// an error if no response arrives within timeout. This guards against the default
// http.Client (used inside ServiceDiscoveryClientV3) having no request deadline.
func getServicesWithTimeout(g schema.IServiceDiscoveryServiceGetter, timeout time.Duration) (schema.IBackendServices, error) {
	type result struct {
		services schema.IBackendServices
		err      error
	}
	ch := make(chan result, 1)
	go func() {
		s, err := servicediscovery.GetServices(g)
		ch <- result{s, err}
	}()
	select {
	case r := <-ch:
		return r.services, r.err
	case <-time.After(timeout):
		return nil, fmt.Errorf("service discovery timed out after %v", timeout)
	}
}

func getClusterName(cfg config.Config) string {
	if clusterName, ok := os.LookupEnv("CLUSTER_NAME"); ok {
		return clusterName
	}
	return cfg.ClusterName
}

func getNamespace(cfg config.Config) string {
	if ns, ok := os.LookupEnv("NAMESPACE"); ok {
		return ns
	}
	if cfg.Namespace != "" {
		return cfg.Namespace
	}

	return defaultNamespace
}

var (
	errServiceDiscoveryNotRegular = errors.New("service discovery file is not a regular file")
	errServiceDiscoveryTooLarge   = errors.New("service discovery file exceeds maximum size limit")
	errCredentialNotRegular       = errors.New("credential file is not a regular file")
	errCredentialTooLarge         = errors.New("credential file exceeds maximum size limit")
)

func joinPreserveSymlinks(dir, name string) string {
	if strings.TrimSpace(dir) == "" {
		return ""
	}
	if os.IsPathSeparator(dir[len(dir)-1]) {
		return dir + name
	}
	return dir + string(os.PathSeparator) + name
}

func readBoundedRegularFile(path string, limit int64, notRegularErr, tooLargeErr error) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, os.ErrNotExist
	}
	statInfo, err := os.Stat(path) //nolint:gosec // G703: path comes from trusted operator configuration (KS_SERVICE_DISCOVERY_FILE_PATH / KS_CREDENTIALS_SECRET_PATH)
	if err != nil {
		return nil, err
	}
	if statInfo.IsDir() {
		return nil, fmt.Errorf("%q is a directory, not a file: %w", path, notRegularErr)
	}
	if !statInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %q", notRegularErr, path)
	}

	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0) //nolint:gosec // G703: path comes from trusted operator configuration (KS_SERVICE_DISCOVERY_FILE_PATH / KS_CREDENTIALS_SECRET_PATH)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%q is a directory, not a file: %w", path, notRegularErr)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %q", notRegularErr, path)
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("%w: %q exceeds the %d byte limit", tooLargeErr, path, limit)
	}

	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		clear(data)
		return nil, err
	}
	if int64(len(data)) > limit {
		clear(data)
		return nil, fmt.Errorf("%w: %q exceeds the %d byte limit", tooLargeErr, path, limit)
	}
	return data, nil
}

func loadCredentialsBounded(secretPath string) (*utils.Credentials, error) {
	creds := &utils.Credentials{}
	limit := filesizelimit.GetMaxFileSize()
	found := false

	fields := []struct {
		key    string
		target *string
	}{
		{key: utils.AccessKeySecretKey, target: &creds.AccessKey},
		{key: utils.AccountSecretKey, target: &creds.Account},
	}
	for _, field := range fields {
		b, err := readBoundedRegularFile(joinPreserveSymlinks(secretPath, field.key), limit, errCredentialNotRegular, errCredentialTooLarge)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, err
		}
		found = true
		*field.target = strings.TrimSuffix(string(b), "\n")
		clear(b)
	}
	if !found {
		return nil, fmt.Errorf("access key and account files are missing in path %s", secretPath)
	}
	return creds, nil
}

func loadAndSetCredentials() {
	credentialsPath := "/etc/credentials"
	if envVar := os.Getenv("KS_CREDENTIALS_SECRET_PATH"); envVar != "" {
		credentialsPath = envVar
	}

	credentials, err := loadCredentialsBounded(credentialsPath)
	if err != nil {
		logger.L().Error("failed to load credentials", helpers.Error(err))
		// fallback (backward compatibility)
		config.SetAccount(os.Getenv("ACCOUNT_ID"))

		return
	}

	logger.L().Info("credentials loaded from path",
		helpers.String("path", credentialsPath),
		helpers.Int("accessKeyLength", len(credentials.AccessKey)),
		helpers.Int("accountLength", len(credentials.Account)))

	config.SetAccessKey(credentials.AccessKey)
	config.SetAccount(credentials.Account)
}
