package policyhandler

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/cautils/getter"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/kubescape/opa-utils/reporthandling"
	"go.opentelemetry.io/otel"
)

const (
	PoliciesCacheTtlEnvVar = "POLICIES_CACHE_TTL"
)

var (
	// Global caches keyed by (clusterName + identifier) to allow sharing across PolicyHandler instances safely
	frameworksCache     = NewTimedCache[[]reporthandling.Framework](getPoliciesCacheTtl())
	exceptionsCache     = NewTimedCache[[]armotypes.PostureExceptionPolicy](getPoliciesCacheTtl())
	controlInputsCache  = NewTimedCache[map[string][]string](getPoliciesCacheTtl())
	identifiersCache     = NewTimedCache[[]string](getPoliciesCacheTtl())
)

// PolicyHandler coordinates policy collection. It is now lightweight and safe for concurrent use.
type PolicyHandler struct {
	clusterName string
}

// NewPolicyHandler creates and returns an instance of the `PolicyHandler`.
func NewPolicyHandler(clusterName string) *PolicyHandler {
	return &PolicyHandler{
		clusterName: clusterName,
	}
}

func (policyHandler *PolicyHandler) CollectPolicies(ctx context.Context, policyIdentifier []cautils.PolicyIdentifier, scanInfo *cautils.ScanInfo) (*cautils.OPASessionObj, error) {
	opaSessionObj := cautils.NewOPASessionObj(ctx, nil, nil, scanInfo)

	// get policies, exceptions and controls inputs
	policies, exceptions, controlInputs, err := policyHandler.getPolicies(ctx, policyIdentifier, &scanInfo.Getters)
	if err != nil {
		return opaSessionObj, err
	}

	opaSessionObj.Policies = policies
	opaSessionObj.Exceptions = exceptions
	opaSessionObj.RegoInputData.PostureControlInputs = controlInputs

	return opaSessionObj, nil
}

func (policyHandler *PolicyHandler) getPolicies(ctx context.Context, policyIdentifier []cautils.PolicyIdentifier, getters *cautils.Getters) (policies []reporthandling.Framework, exceptions []armotypes.PostureExceptionPolicy, controlInputs map[string][]string, err error) {
	ctx, span := otel.Tracer("").Start(ctx, "policyHandler.getPolicies")
	defer span.End()

	logger.L().Start("Loading policies...")

	// get policies
	policies, err = policyHandler.getScanPolicies(ctx, policyIdentifier, getters)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(policies) == 0 {
		return nil, nil, nil, fmt.Errorf("failed to download policies: '%s'. Make sure the policy exist and you spelled it correctly. For more information, please feel free to contact ARMO team", strings.Join(policyIdentifierToSlice(policyIdentifier), ", "))
	}

	logger.L().StopSuccess("Loaded policies")
	logger.L().Start("Loading exceptions...")

	// get exceptions
	if exceptions, err = policyHandler.getExceptions(getters); err != nil {
		logger.L().Ctx(ctx).Warning("failed to load exceptions", helpers.Error(err))
	}

	logger.L().StopSuccess("Loaded exceptions")
	logger.L().Start("Loading account configurations...")

	// get account configuration
	if controlInputs, err = policyHandler.getControlInputs(getters); err != nil {
		logger.L().Ctx(ctx).Warning(err.Error())
	}

	logger.L().StopSuccess("Loaded account configurations")

	return policies, exceptions, controlInputs, nil
}

// getScanPolicies - get policies from cache or downloads them.
func (policyHandler *PolicyHandler) getScanPolicies(ctx context.Context, policyIdentifier []cautils.PolicyIdentifier, getters *cautils.Getters) ([]reporthandling.Framework, error) {
	policyIdentifiersSlice := policyIdentifierToSlice(policyIdentifier)
	cacheKey := strings.Join(policyIdentifiersSlice, ",")

	// check if policies are cached
	if cachedPolicies, policiesExist := frameworksCache.GetWithKey(cacheKey); policiesExist {
		logger.L().Info("Using cached policies")
		return deepCopyPolicies(cachedPolicies)
	}

	policies, err := policyHandler.downloadScanPolicies(ctx, policyIdentifier, getters)
	if err == nil {
		frameworksCache.SetWithKey(cacheKey, policies)
	}

	return policies, err
}

func deepCopyPolicies(src []reporthandling.Framework) ([]reporthandling.Framework, error) {
	data, err := json.Marshal(src)
	if err != nil {
		return nil, err
	}
	var dst []reporthandling.Framework
	err = json.Unmarshal(data, &dst)
	if err != nil {
		return nil, err
	}

	return dst, nil
}

func (policyHandler *PolicyHandler) downloadScanPolicies(ctx context.Context, policyIdentifier []cautils.PolicyIdentifier, getters *cautils.Getters) ([]reporthandling.Framework, error) {
	frameworks := []reporthandling.Framework{}

	switch getScanKind(policyIdentifier) {
	case apisv1.KindFramework: // Download frameworks
		for _, rule := range policyIdentifier {
			logger.L().Debug("Downloading framework", helpers.String("framework", rule.Identifier))
			receivedFramework, err := getters.PolicyGetter.GetFramework(rule.Identifier)
			if err != nil {
				return frameworks, frameworkDownloadError(err, rule.Identifier)
			}
			if err := validateFramework(receivedFramework); err != nil {
				return frameworks, err
			}
			if receivedFramework != nil {
				frameworks = append(frameworks, *receivedFramework)
				cache := getter.GetDefaultPath(rule.Identifier + ".json")
				if _, ok := getters.PolicyGetter.(*getter.LoadPolicy); ok {
					continue // skip caching for local files
				}
				if err := getter.SaveInFile(receivedFramework, cache); err != nil {
					logger.L().Ctx(ctx).Warning("failed to cache framework", helpers.String("file", cache), helpers.Error(err))
				}
			}
		}
	case apisv1.KindControl: // Download controls
		f := reporthandling.Framework{}
		var receivedControl *reporthandling.Control
		var err error
		for _, policy := range policyIdentifier {
			logger.L().Debug("Downloading control", helpers.String("control", policy.Identifier))
			receivedControl, err = getters.PolicyGetter.GetControl(policy.Identifier)
			if err != nil {
				return frameworks, controlDownloadError(err, policy.Identifier)
			}
			if receivedControl != nil {
				f.Controls = append(f.Controls, *receivedControl)

				cache := getter.GetDefaultPath(policy.Identifier + ".json")
				if err := getter.SaveInFile(receivedControl, cache); err != nil {
					logger.L().Ctx(ctx).Warning("failed to cache control", helpers.String("file", cache), helpers.Error(err))
				}
			}
		}
		frameworks = append(frameworks, f)
		// TODO: add case for control from file
	default:
		return frameworks, fmt.Errorf("unknown policy kind")
	}
	return frameworks, nil
}

func (policyHandler *PolicyHandler) getExceptions(getters *cautils.Getters) ([]armotypes.PostureExceptionPolicy, error) {
	if cachedExceptions, exist := exceptionsCache.GetWithKey(policyHandler.clusterName); exist {
		logger.L().Info("Using cached exceptions")
		return cachedExceptions, nil
	}

	exceptions, err := getters.ExceptionsGetter.GetExceptions(policyHandler.clusterName)
	if err == nil {
		exceptionsCache.SetWithKey(policyHandler.clusterName, exceptions)
	}

	return exceptions, err
}

func (policyHandler *PolicyHandler) getControlInputs(getters *cautils.Getters) (map[string][]string, error) {
	if cachedControlInputs, exist := controlInputsCache.GetWithKey(policyHandler.clusterName); exist {
		logger.L().Info("Using cached control inputs")
		return cachedControlInputs, nil
	}

	controlInputs, err := getters.ControlsInputsGetter.GetControlsInputs(policyHandler.clusterName)
	if err == nil {
		controlInputsCache.SetWithKey(policyHandler.clusterName, controlInputs)
	}

	return controlInputs, err
}
