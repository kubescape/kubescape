package policyhandler

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/kubescape/opa-utils/reporthandling"
	"go.opentelemetry.io/otel"
)

const (
	PoliciesCacheTtlEnvVar = "POLICIES_CACHE_TTL"
)

type cachedPoliciesEntry struct {
	identifiers []string
	frameworks  []reporthandling.Framework
}

type policyArtifactPersistence interface {
	ShouldPersistPolicyArtifacts() bool
}

// PolicyHandler
type PolicyHandler struct {
	clusterName         string
	cachedPolicies      *TimedCache[cachedPoliciesEntry]
	cachedExceptions    *TimedCache[[]armotypes.PostureExceptionPolicy]
	cachedControlInputs *TimedCache[map[string][]string]
}

// NewPolicyHandler returns the shared, cluster-isolated *PolicyHandler for
// clusterName from the process-wide registry (see registry.go). Callers that
// repeatedly scan the same cluster (the httphandler HTTP service, in
// particular - see core/core/scan.go) keep the POLICIES_CACHE_TTL caching
// benefit across calls; callers for a different cluster get a completely
// separate instance, so a later call never silently reuses an earlier
// cluster's exception/control-input caches. Handlers with nothing actively
// using them are reclaimed by an idle sweep rather than requiring callers to
// release them, so this stays memory-bounded even in a long-running process
// that sees many distinct cluster names over its lifetime.
// Shared handlers are owned and managed by globalRegistry; callers MUST NOT call Close() directly.
func NewPolicyHandler(clusterName string) *PolicyHandler {
	return globalRegistry.getHandler(clusterName)
}

// NewPolicyHandlerWithRelease returns the shared PolicyHandler for
// clusterName and a release function that must be deferred. Intended for
// orchestration paths - e.g. the fleet work in issue #1990 - that scan the
// same cluster sequentially in one goroutine and want the cache reuse
// guaranteed for that duration rather than left to the idle sweep.
func NewPolicyHandlerWithRelease(clusterName string) (*PolicyHandler, func()) {
	return globalRegistry.acquireHandler(clusterName)
}

// NewRequestScopedPolicyHandler creates and returns a new, independent instance of the `PolicyHandler`.
// The returned instance is unmanaged and request-scoped; callers ARE responsible for calling Close() when finished.
func NewRequestScopedPolicyHandler(clusterName string) *PolicyHandler {
	cacheTtl := getPoliciesCacheTtl()
	return &PolicyHandler{
		clusterName:         clusterName,
		cachedPolicies:      NewTimedCache[cachedPoliciesEntry](cacheTtl),
		cachedExceptions:    NewTimedCache[[]armotypes.PostureExceptionPolicy](cacheTtl),
		cachedControlInputs: NewTimedCache[map[string][]string](cacheTtl),
	}
}

// Close stops all internal caches and background goroutines to prevent leaks.
func (policyHandler *PolicyHandler) Close() {
	if policyHandler.cachedPolicies != nil {
		policyHandler.cachedPolicies.Stop()
	}
	if policyHandler.cachedExceptions != nil {
		policyHandler.cachedExceptions.Stop()
	}
	if policyHandler.cachedControlInputs != nil {
		policyHandler.cachedControlInputs.Stop()
	}
}

func (policyHandler *PolicyHandler) CollectPolicies(ctx context.Context, policyIdentifier []cautils.PolicyIdentifier, scanInfo *cautils.ScanInfo, getters *cautils.Getters) (*cautils.OPASessionObj, error) {
	// get policies, exceptions and controls inputs
	policies, exceptions, controlInputs, degradations, err := policyHandler.getPolicies(ctx, policyIdentifier, getters)
	if err != nil {
		return cautils.NewOPASessionObj(ctx, nil, nil, scanInfo, policyIdentifier), err
	}
	cautils.RecordScanContractRunnerInputs(scanInfo, getters)
	opaSessionObj := cautils.NewOPASessionObj(ctx, nil, nil, scanInfo, policyIdentifier)

	// load user-authored custom rules, if any
	if scanInfo.CustomRules != "" {
		customFramework, err := getter.LoadCustomRules(scanInfo.CustomRules)
		if err != nil {
			return opaSessionObj, err
		}
		if customFramework != nil {
			policies = append(policies, *customFramework)
		}
	}

	if scanInfo != nil && len(scanInfo.ExcludeControls) > 0 {
		result, err := excludeControls(policies, scanInfo.ExcludeControls)
		if err != nil {
			return opaSessionObj, err
		}
		if len(result.unmatched) > 0 {
			logger.L().Ctx(ctx).Warning("--exclude-controls matched no control",
				helpers.String("controls", quoteIdentifiers(result.unmatched)))
		}
		logger.L().Info("Controls excluded from the scan", helpers.Int("count", result.excluded))
		policies = result.policies
	}

	opaSessionObj.Policies = policies
	opaSessionObj.Exceptions = exceptions
	if controlInputs == nil {
		controlInputs = map[string][]string{}
	}
	opaSessionObj.RegoInputData.PostureControlInputs = controlInputs
	opaSessionObj.PolicyDegradations = degradations

	return opaSessionObj, nil
}

func (policyHandler *PolicyHandler) getPolicies(ctx context.Context, policyIdentifier []cautils.PolicyIdentifier, getters *cautils.Getters) (policies []reporthandling.Framework, exceptions []armotypes.PostureExceptionPolicy, controlInputs map[string][]string, degradations []cautils.PolicyDegradation, err error) {
	ctx, span := otel.Tracer("").Start(ctx, "policyHandler.getPolicies")
	defer span.End()

	logger.L().Start("Loading policies...")

	// get policies
	policies, err = policyHandler.getScanPolicies(ctx, policyIdentifier, getters)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if len(policies) == 0 {
		return nil, nil, nil, nil, fmt.Errorf("failed to download policies: '%s'. Make sure the policy exist and you spelled it correctly. For more information, please feel free to contact ARMO team", strings.Join(policyIdentifierToSlice(policyIdentifier), ", "))
	}

	logger.L().StopSuccess("Loaded policies")
	logger.L().Start("Loading exceptions...")

	// get exceptions
	if exceptions, err = policyHandler.getExceptions(ctx, getters); err != nil {
		logger.L().Ctx(ctx).StopError("Failed to load exceptions", helpers.Error(err))
		degradations = append(degradations, cautils.PolicyDegradation{Component: "exceptions", Reason: err.Error()})
		exceptions = []armotypes.PostureExceptionPolicy{}
	} else {
		logger.L().StopSuccess("Loaded exceptions")
	}

	logger.L().Start("Loading account configurations...")

	// get account configuration
	if controlInputs, err = policyHandler.getControlInputs(ctx, getters); err != nil {
		logger.L().Ctx(ctx).StopError("Failed to load account configurations", helpers.Error(err))
		degradations = append(degradations, cautils.PolicyDegradation{Component: "controlInputs", Reason: err.Error()})

		if defaultInputs, defaultErr := getter.DefaultControlInputs(); defaultErr == nil {
			controlInputs = defaultInputs
		} else {
			logger.L().Ctx(ctx).Warning("failed to load bundled default control inputs", helpers.Error(defaultErr))
			degradations = append(degradations, cautils.PolicyDegradation{Component: "controlInputs", Reason: defaultErr.Error()})
		}
	} else {
		logger.L().StopSuccess("Loaded account configurations")
	}

	return policies, exceptions, controlInputs, degradations, nil
}

// getScanPolicies - get policies from cache or downloads them. The function returns an error if the policies could not be downloaded.
func (policyHandler *PolicyHandler) getScanPolicies(ctx context.Context, policyIdentifier []cautils.PolicyIdentifier, getters *cautils.Getters) ([]reporthandling.Framework, error) {
	policyIdentifiersSlice := policyIdentifierToSlice(policyIdentifier)
	_, isLocalPolicy := getters.PolicyGetter.(*getter.LoadPolicy)
	// Explicit local policy sources are request-scoped inputs. They must not be
	// shadowed by, or replace, a shared cache entry for the same identifiers.
	if !isLocalPolicy {
		// check if policies are cached atomically
		if entry, exist := policyHandler.cachedPolicies.Get(); exist {
			// check if the cached policies match the requested policy identifiers
			if cautils.StringSlicesAreEqual(entry.identifiers, policyIdentifiersSlice) {
				logger.L().Info("Using cached policies")
				return deepCopyPolicies(entry.frameworks)
			}

			logger.L().Debug("Cached policies are not the same as the requested policies")
			policyHandler.cachedPolicies.Invalidate()
		}
	}

	policies, err := policyHandler.downloadScanPolicies(ctx, policyIdentifier, getters)
	if err == nil && !isLocalPolicy {
		policyHandler.cachedPolicies.Set(cachedPoliciesEntry{
			identifiers: policyIdentifiersSlice,
			frameworks:  policies,
		})
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
	persistPolicyArtifacts := true
	if persistence, ok := getters.PolicyGetter.(policyArtifactPersistence); ok {
		persistPolicyArtifacts = persistence.ShouldPersistPolicyArtifacts()
	}

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
				if !persistPolicyArtifacts {
					continue
				}
				cache, err := getter.PolicyCachePath(rule.Identifier)
				if err != nil {
					logger.L().Ctx(ctx).Warning("skipping framework cache write", helpers.String("identifier", rule.Identifier), helpers.Error(err))
					continue
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
				if !persistPolicyArtifacts {
					continue
				}
				cache, err := getter.PolicyCachePath(policy.Identifier)
				if err != nil {
					logger.L().Ctx(ctx).Warning("skipping control cache write", helpers.String("identifier", policy.Identifier), helpers.Error(err))
					continue
				}
				if err := getter.SaveInFile(receivedControl, cache); err != nil {
					logger.L().Ctx(ctx).Warning("failed to cache control", helpers.String("file", cache), helpers.Error(err))
				}
			}
		}
		frameworks = append(frameworks, f)
	default:
		return frameworks, fmt.Errorf("unknown policy kind")
	}
	return frameworks, nil
}

func (policyHandler *PolicyHandler) getExceptions(ctx context.Context, getters *cautils.Getters) ([]armotypes.PostureExceptionPolicy, error) {
	if cachedExceptions, exist := policyHandler.cachedExceptions.Get(); exist {
		logger.L().Info("Using cached exceptions")
		return cachedExceptions, nil
	}

	exceptions, err := getters.ExceptionsGetter.GetExceptions(ctx, policyHandler.clusterName)
	if err == nil {
		policyHandler.cachedExceptions.Set(exceptions)
	}

	return exceptions, err
}

func (policyHandler *PolicyHandler) getControlInputs(ctx context.Context, getters *cautils.Getters) (map[string][]string, error) {
	if cachedControlInputs, exist := policyHandler.cachedControlInputs.Get(); exist {
		logger.L().Info("Using cached control inputs")
		return cachedControlInputs, nil
	}

	controlInputs, err := getters.ControlsInputsGetter.GetControlsInputs(ctx, policyHandler.clusterName)
	if err != nil {
		return nil, err
	}
	if len(controlInputs) == 0 {
		return nil, fmt.Errorf("no control configuration inputs available")
	}

	policyHandler.cachedControlInputs.Set(controlInputs)
	return controlInputs, nil
}
