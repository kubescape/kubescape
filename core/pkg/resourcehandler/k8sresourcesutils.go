package resourcehandler

import (
	"fmt"
	"slices"
	"strings"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/hostsensorutils"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/kubescape/opa-utils/reporthandling"
)

var (
	ClusterDescribe              = "ClusterDescribe"
	DescribeRepositories         = "DescribeRepositories"
	ListEntitiesForPolicies      = "ListEntitiesForPolicies"
	PolicyVersion                = "PolicyVersion"
	APIServerInfo                = "APIServerInfo"
	KubeletConfiguration         = "KubeletConfiguration"
	OsReleaseFile                = "OsReleaseFile"
	KernelVersion                = "KernelVersion"
	LinuxSecurityHardeningStatus = "LinuxSecurityHardeningStatus"
	OpenPortsList                = "OpenPortsList"
	LinuxKernelVariables         = "LinuxKernelVariables"
	KubeletCommandLine           = "KubeletCommandLine"
	ImageVulnerabilities         = "ImageVulnerabilities"
	KubeletInfo                  = "KubeletInfo"
	KubeProxyInfo                = "KubeProxyInfo"
	ControlPlaneInfo             = "ControlPlaneInfo"
	CloudProviderInfo            = "CloudProviderInfo"
	CNIInfo                      = "CNIInfo"

	MapResourceToApiGroup = map[string]string{
		KubeletConfiguration:         "hostdata.kubescape.cloud/v1beta0",
		OsReleaseFile:                "hostdata.kubescape.cloud/v1beta0",
		KubeletCommandLine:           "hostdata.kubescape.cloud/v1beta0",
		KernelVersion:                "hostdata.kubescape.cloud/v1beta0",
		LinuxSecurityHardeningStatus: "hostdata.kubescape.cloud/v1beta0",
		OpenPortsList:                "hostdata.kubescape.cloud/v1beta0",
		LinuxKernelVariables:         "hostdata.kubescape.cloud/v1beta0",
		KubeletInfo:                  "hostdata.kubescape.cloud/v1beta0",
		KubeProxyInfo:                "hostdata.kubescape.cloud/v1beta0",
		ControlPlaneInfo:             "hostdata.kubescape.cloud/v1beta0",
		CloudProviderInfo:            "hostdata.kubescape.cloud/v1beta0",
		CNIInfo:                      "hostdata.kubescape.cloud/v1beta0",
	}
	MapResourceToApiGroupVuln = map[string][]string{
		ImageVulnerabilities: {"armo.vuln.images/v1", "image.vulnscan.com/v1"}}
	// MapResourceToApiGroupCloud also holds APIServerInfo: it is built from the
	// API server's version endpoint, not a cloud provider, but it is selected
	// and collected together with the cloud resources (cautils.CloudResources).
	MapResourceToApiGroupCloud = map[string][]string{
		ClusterDescribe:         {"container.googleapis.com/v1", "eks.amazonaws.com/v1", "management.azure.com/v1"},
		DescribeRepositories:    {"container.googleapis.com/v1", "eks.amazonaws.com/v1"}, //TODO - add azure when ensure-image-scanning-enabled-cloud supports ACR
		ListEntitiesForPolicies: {"container.googleapis.com/v1", "eks.amazonaws.com/v1", "management.azure.com/v1"},
		PolicyVersion:           {"eks.amazonaws.com/v1", "management.azure.com/v1"},
		APIServerInfo:           {"apiserverinfo.kubescape.cloud/v1beta0"},
	}
)

func isEmptyImgVulns(externalResourcesMap cautils.ExternalResources) bool {
	imgVulnResources := cautils.MapImageVulnResources(externalResourcesMap)
	for _, resource := range imgVulnResources {
		if val, ok := externalResourcesMap[resource]; ok {
			if len(val) > 0 {
				return false
			}
		}
	}
	return true
}

func setKSResourceMap(frameworks []reporthandling.Framework, resourceToControl map[string][]string, resolver resourceResolver) cautils.ExternalResources {
	externalResources := make(cautils.ExternalResources)
	complexMap := setComplexKSResourceMap(frameworks, resourceToControl, resolver)
	for group := range complexMap {
		for version := range complexMap[group] {
			for resource := range complexMap[group][version] {
				for _, resolved := range resolver(group, version, resource) {
					externalResources[resolved.groupVersionResourceTriplet] = nil
				}
			}
		}
	}
	return externalResources
}

// [group][version][resource]
func setComplexKSResourceMap(frameworks []reporthandling.Framework, resourceToControls map[string][]string, resolver resourceResolver) map[string]map[string]map[string]any {
	k8sResources := make(map[string]map[string]map[string]any)
	for _, framework := range frameworks {
		for _, control := range framework.Controls {
			for _, rule := range control.Rules {
				for _, match := range rule.Match {
					insertKSResourcesAndControls(k8sResources, match, resourceToControls, control)
					for _, apiGroup := range match.APIGroups {
						for _, apiVersion := range match.APIVersions {
							for _, resource := range match.Resources {
								for _, resolved := range resolver(apiGroup, apiVersion, resource) {
									resourceGroup := resolved.groupVersionResourceTriplet
									if !slices.Contains(resourceToControls[resourceGroup], control.ControlID) {
										resourceToControls[resourceGroup] = append(resourceToControls[resourceGroup], control.ControlID)
									}
								}
							}
						}
					}
				}
				for _, match := range rule.DynamicMatch {
					insertKSResourcesAndControls(k8sResources, match, resourceToControls, control)
					insertDynamicMatchControls(k8sResources, match, resourceToControls, control)
				}
			}
		}
	}
	return k8sResources
}

func mapKSResourceToApiGroup(resource string) []string {
	if val, ok := MapResourceToApiGroup[resource]; ok {
		return []string{val}
	}
	if val, ok := MapResourceToApiGroupCloud[resource]; ok {
		return val
	}
	if val, ok := MapResourceToApiGroupVuln[resource]; ok {
		return val
	}
	return []string{}
}

// isUnservedKSIdentity reports whether group/version/resource names a group
// Kubescape serves itself (host data, cloud, image vulnerabilities) without
// being one of the identities registered for resource in the maps above. C-0161
// reads APIServerInfo under the host-data group: no cluster and no Kubescape
// collector serves that one, so it must not become a live query just because
// the resource name is known. References under any other group keep resolving
// by name as before, and a "*" version matches any version registered under the
// group, as the DynamicMatch evaluator accepts it.
func isUnservedKSIdentity(group, version, resource string) bool {
	registered := mapKSResourceToApiGroup(resource)
	if len(registered) == 0 || !isKSServedGroup(group) {
		return false
	}
	for _, apiVersion := range registered {
		g, v := k8sinterface.SplitApiVersion(apiVersion)
		if g == group && (version == "*" || version == v) {
			return false
		}
	}
	return true
}

// isKSServedGroup reports whether group is one of the API groups of the
// resources Kubescape serves itself.
func isKSServedGroup(group string) bool {
	for _, apiVersion := range MapResourceToApiGroup {
		if g, _ := k8sinterface.SplitApiVersion(apiVersion); g == group {
			return true
		}
	}
	for _, families := range []map[string][]string{MapResourceToApiGroupCloud, MapResourceToApiGroupVuln} {
		for _, apiVersions := range families {
			for _, apiVersion := range apiVersions {
				if g, _ := k8sinterface.SplitApiVersion(apiVersion); g == group {
					return true
				}
			}
		}
	}
	return false
}

// isExternalResource reports whether a resolved group/version/resource triplet
// names a resource Kubescape serves itself - host sensor data, cloud provider
// descriptions, image vulnerabilities. Their API groups belong to Kubescape, so
// no cluster ever serves them and they are never collected with a LIST.
func isExternalResource(triplet string) bool {
	_, _, resource := k8sinterface.StringToResourceGroup(triplet)
	return len(mapKSResourceToApiGroup(resource)) > 0
}

func insertControls(resource string, resourceToControl map[string][]string, control reporthandling.Control) {
	ksResources := mapKSResourceToApiGroup(resource)
	for _, ksResource := range ksResources {
		group, version := k8sinterface.SplitApiVersion(ksResource)
		r := k8sinterface.JoinResourceTriplets(group, version, resource)
		if !slices.Contains(resourceToControl[r], control.ControlID) {
			resourceToControl[r] = append(resourceToControl[r], control.ControlID)
		}
	}
}

// insertDynamicMatchControls records control as depending on every
// Kubescape-served resource its DynamicMatch selects, using the evaluator's
// matching rules (getKubernetesObjects in opaprocessor): "*" for any group,
// version or resource, "core" for the empty group, and resource names compared
// case-insensitively. insertControls only looks resource names up exactly, so
// a rule written with "*" or another case would otherwise read the resource
// without the dependency being recorded, and a failed pull of it would not be
// attributed to the control. The virtual identities of these resources use the
// kind as the resource name, so matching by name also covers matching by kind.
//
// Each selected identity is also added to k8sResources, so it is collected (or
// its failure recorded) like a name the rule spelled out. A dependency that is
// never requested has no failure entry, and BuildScanCoverage would read it as
// collected and count the control as evaluated. For the same reason only the
// host kinds the host sensor collects are selected: the legacy names left in
// MapResourceToApiGroup never get a status from it.
func insertDynamicMatchControls(k8sResources map[string]map[string]map[string]any, match reporthandling.RuleMatchObjects, resourceToControl map[string][]string, control reporthandling.Control) {
	add := func(resource string, apiVersions []string) {
		for _, apiVersion := range apiVersions {
			group, version := k8sinterface.SplitApiVersion(apiVersion)
			if !dynamicMatchSelects(match, group, version, resource) {
				continue
			}
			if k8sResources[group] == nil {
				k8sResources[group] = make(map[string]map[string]any)
			}
			if k8sResources[group][version] == nil {
				k8sResources[group][version] = make(map[string]any)
			}
			k8sResources[group][version][resource] = nil
			r := k8sinterface.JoinResourceTriplets(group, version, resource)
			if !slices.Contains(resourceToControl[r], control.ControlID) {
				resourceToControl[r] = append(resourceToControl[r], control.ControlID)
			}
		}
	}
	for _, resource := range hostsensorutils.CollectedResources() {
		add(resource.String(), []string{MapResourceToApiGroup[resource.String()]})
	}
	for resource, apiVersions := range MapResourceToApiGroupCloud {
		add(resource, apiVersions)
	}
	for resource, apiVersions := range MapResourceToApiGroupVuln {
		add(resource, apiVersions)
	}
}

// dynamicMatchSelects reports whether match selects group/version/resource.
func dynamicMatchSelects(match reporthandling.RuleMatchObjects, group, version, resource string) bool {
	matches := func(policyValue, value string) bool {
		return policyValue == "*" || policyValue == value || (policyValue == "core" && value == "")
	}
	return slices.ContainsFunc(match.APIGroups, func(g string) bool { return matches(g, group) }) &&
		slices.ContainsFunc(match.APIVersions, func(v string) bool { return matches(v, version) }) &&
		slices.ContainsFunc(match.Resources, func(r string) bool { return r == "*" || strings.EqualFold(r, resource) })
}

func insertKSResourcesAndControls(k8sResources map[string]map[string]map[string]any, match reporthandling.RuleMatchObjects, resourceToControl map[string][]string, control reporthandling.Control) {
	for _, apiGroup := range match.APIGroups {
		if v, ok := k8sResources[apiGroup]; !ok || v == nil {
			k8sResources[apiGroup] = make(map[string]map[string]any)
		}
		for _, apiVersions := range match.APIVersions {
			if v, ok := k8sResources[apiGroup][apiVersions]; !ok || v == nil {
				k8sResources[apiGroup][apiVersions] = make(map[string]any)
			}
			for _, resource := range match.Resources {
				if _, ok := k8sResources[apiGroup][apiVersions][resource]; !ok {
					k8sResources[apiGroup][apiVersions][resource] = nil
				}
				insertControls(resource, resourceToControl, control)
			}
		}
	}
}

func getGroupNVersion(apiVersion string) (string, string) {
	gv := strings.Split(apiVersion, "/")
	group, version := "", ""
	if len(gv) == 1 {
		version = gv[0]
	} else if len(gv) >= 2 {
		group = gv[0]
		version = gv[1]
	}
	return group, version
}

// getFieldSelectorFromScanInfo picks the namespace filter the collection queries
// carry. A flag is honored only when its value actually names a namespace: a
// value made of separators and whitespace ("," or " ") narrows nothing, which is
// already how countNamespaces and the report metadata read it, and an include
// selector built from one emits no query at all (see GetNamespacesSelectors).
func getFieldSelectorFromScanInfo(scanInfo *cautils.ScanInfo) IFieldSelector {
	if len(splitNamespaces(scanInfo.IncludeNamespaces)) > 0 {
		return NewIncludeSelector(scanInfo.IncludeNamespaces)
	}
	if len(splitNamespaces(scanInfo.ExcludedNamespaces)) > 0 {
		return NewExcludeSelector(scanInfo.ExcludedNamespaces)
	}

	return &EmptySelector{}
}

func getWorkloadFromScanObject(resource *objectsenvelopes.ScanObject) (workloadinterface.IWorkload, error) {
	if resource == nil {
		return nil, nil
	}
	obj := resource.GetObject()
	if k8sinterface.IsTypeWorkload(obj) {
		return workloadinterface.NewWorkloadObj(obj), nil
	}
	return nil, fmt.Errorf("resource %s is not a valid workload", k8sinterface.GetReadableID(resource))
}
