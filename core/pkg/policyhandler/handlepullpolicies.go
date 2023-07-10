package policyhandler

import (
	"context"
	"fmt"
	"strings"

	"github.com/armosec/armoapi-go/armotypes"
	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/cautils/getter"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/kubescape/opa-utils/reporthandling"
	"go.opentelemetry.io/otel"
)

const (
	PoliciesCacheTtlEnvVar = "POLICIES_CACHE_TTL"
)

var policyHandlerInstance *PolicyHandler

// PolicyHandler
type PolicyHandler struct {
	getters                 *cautils.Getters
	cachedPolicyIdentifiers *TimedCache[[]string]
	cachedFrameworks        *TimedCache[[]reporthandling.Framework]
	cachedExceptions        *TimedCache[[]armotypes.PostureExceptionPolicy]
}

// NewPolicyHandler creates and returns an instance of the `PolicyHandler`. The function initializes the `PolicyHandler` only if it hasn't been previously created.
// The PolicyHandler supports caching of downloaded policies and exceptions by setting the `POLICIES_CACHE_TTL` environment variable (default is no caching).
func NewPolicyHandler() *PolicyHandler {
	if policyHandlerInstance == nil {
		cacheTtl := getPoliciesCacheTtl()
		policyHandlerInstance = &PolicyHandler{
			cachedPolicyIdentifiers: NewTimedCache[[]string](cacheTtl),
			cachedFrameworks:        NewTimedCache[[]reporthandling.Framework](cacheTtl),
			cachedExceptions:        NewTimedCache[[]armotypes.PostureExceptionPolicy](cacheTtl),
		}
	}
	return policyHandlerInstance
}

func (policyHandler *PolicyHandler) CollectPolicies(ctx context.Context, policyIdentifier []cautils.PolicyIdentifier, scanInfo *cautils.ScanInfo) (*cautils.OPASessionObj, error) {
	opaSessionObj := cautils.NewOPASessionObj(ctx, nil, nil, scanInfo)

	policyHandler.getters = &scanInfo.Getters

	// get policies, exceptions and controls inputs
	policies, exceptions, controlInputs, err := policyHandler.getPolicies(ctx, policyIdentifier)
	if err != nil {
		return opaSessionObj, err
	}

	opaSessionObj.Policies = policies
	opaSessionObj.Exceptions = exceptions
	opaSessionObj.RegoInputData.PostureControlInputs = controlInputs

	return opaSessionObj, nil
}

func (policyHandler *PolicyHandler) getPolicies(ctx context.Context, policyIdentifier []cautils.PolicyIdentifier) (policies []reporthandling.Framework, exceptions []armotypes.PostureExceptionPolicy, controlInputs map[string][]string, err error) {
	ctx, span := otel.Tracer("").Start(ctx, "policyHandler.getPolicies")
	defer span.End()
	logger.L().Info("Downloading/Loading policy definitions")

	cautils.StartSpinner()
	defer cautils.StopSpinner()

	// get policies
	policies, err = policyHandler.getScanPolicies(ctx, policyIdentifier)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(policies) == 0 {
		return nil, nil, nil, fmt.Errorf("failed to download policies: '%s'. Make sure the policy exist and you spelled it correctly. For more information, please feel free to contact ARMO team", strings.Join(policyIdentifierToSlice(policyIdentifier), ", "))
	}

	// get exceptions
	if exceptions, err = policyHandler.getExceptions(); err != nil {
		logger.L().Ctx(ctx).Warning("failed to load exceptions", helpers.Error(err))
	}

	// get account configuration
	if controlInputs, err = policyHandler.getters.ControlsInputsGetter.GetControlsInputs(cautils.ClusterName); err != nil {
		logger.L().Ctx(ctx).Warning(err.Error())
	}

	cautils.StopSpinner()
	logger.L().Success("Downloaded/Loaded policy")

	return policies, exceptions, controlInputs, nil
}

// getScanPolicies - get policies from cache or downloads them. The function returns an error if the policies could not be downloaded.
func (policyHandler *PolicyHandler) getScanPolicies(ctx context.Context, policyIdentifier []cautils.PolicyIdentifier) ([]reporthandling.Framework, error) {
	policyIdentifiersSlice := policyIdentifierToSlice(policyIdentifier)
	// check if policies are cached
	if cachedPolicies, policiesExist := policyHandler.cachedFrameworks.Get(); policiesExist {
		// check if the cached policies are the same as the requested policies, otherwise download the policies
		if cachedIdentifiers, identifiersExist := policyHandler.cachedPolicyIdentifiers.Get(); identifiersExist && cautils.StringSlicesAreEqual(cachedIdentifiers, policyIdentifiersSlice) {
			logger.L().Info("Using cached policies")
			return cachedPolicies, nil
		}

		logger.L().Debug("Cached policies are not the same as the requested policies")
		policyHandler.cachedPolicyIdentifiers.Invalidate()
		policyHandler.cachedFrameworks.Invalidate()
	}

	policies, err := policyHandler.downloadScanPolicies(ctx, policyIdentifier)
	if err == nil {
		policyHandler.cachedFrameworks.Set(policies)
		policyHandler.cachedPolicyIdentifiers.Set(policyIdentifiersSlice)
	}

	return policies, err
}

func (policyHandler *PolicyHandler) downloadScanPolicies(ctx context.Context, policyIdentifier []cautils.PolicyIdentifier) ([]reporthandling.Framework, error) {
	frameworks := []reporthandling.Framework{}

	switch getScanKind(policyIdentifier) {
	case apisv1.KindFramework: // Download frameworks
		for _, rule := range policyIdentifier {
			logger.L().Debug("Downloading framework", helpers.String("framework", rule.Identifier))
			receivedFramework, err := policyHandler.getters.PolicyGetter.GetFramework(rule.Identifier)
			if err != nil {
				return frameworks, policyDownloadError(err)
			}
			if err := validateFramework(receivedFramework); err != nil {
				return frameworks, err
			}
			if receivedFramework != nil {
				frameworks = append(frameworks, *receivedFramework)
				cache := getter.GetDefaultPath(rule.Identifier + ".json")
				if err := getter.SaveInFile(receivedFramework, cache); err != nil {
					logger.L().Ctx(ctx).Warning("failed to cache file", helpers.String("file", cache), helpers.Error(err))
				}
			}
		}
	case apisv1.KindControl: // Download controls
		f := reporthandling.Framework{}
		var receivedControl *reporthandling.Control
		var err error
		for _, policy := range policyIdentifier {
			logger.L().Debug("Downloading control", helpers.String("control", policy.Identifier))
			receivedControl, err = policyHandler.getters.PolicyGetter.GetControl(policy.Identifier)
			if err != nil {
				return frameworks, policyDownloadError(err)
			}
			if receivedControl != nil {
				f.Controls = append(f.Controls, *receivedControl)

				cache := getter.GetDefaultPath(policy.Identifier + ".json")
				if err := getter.SaveInFile(receivedControl, cache); err != nil {
					logger.L().Ctx(ctx).Warning("failed to cache file", helpers.String("file", cache), helpers.Error(err))
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

func (policyHandler *PolicyHandler) getExceptions() ([]armotypes.PostureExceptionPolicy, error) {
	if cachedExceptions, exist := policyHandler.cachedExceptions.Get(); exist {
		logger.L().Info("Using cached exceptions")
		return cachedExceptions, nil
	}

	exceptions, err := policyHandler.getters.ExceptionsGetter.GetExceptions(cautils.ClusterName)
	if err == nil {
		policyHandler.cachedExceptions.Set(exceptions)
	}

	return exceptions, err
}
