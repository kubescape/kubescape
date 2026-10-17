package mcpserver

import (
	"context"
	"encoding/json"
	"testing"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	storagev1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	storagefake "github.com/kubescape/storage/pkg/generated/clientset/versioned/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func sbomPackage(name, version, pkgType string, licenses ...storagev1beta1.License) storagev1beta1.SyftPackage {
	return storagev1beta1.SyftPackage{PackageBasicData: storagev1beta1.PackageBasicData{
		ID:       name + "@" + version,
		Name:     name,
		Version:  version,
		Type:     pkgType,
		PURL:     "pkg:" + pkgType + "/" + name + "@" + version,
		Licenses: licenses,
		Locations: []storagev1beta1.Location{{LocationData: storagev1beta1.LocationData{
			Coordinates: storagev1beta1.Coordinates{RealPath: "/var/lib/dpkg/status"},
		}}},
	}}
}

func sbomListServer(t *testing.T) *KubescapeMcpserver {
	t.Helper()
	sbom := &storagev1beta1.SBOMSyft{
		ObjectMeta: metav1.ObjectMeta{Name: "nginx-1.21", Namespace: "kubescape", Annotations: map[string]string{
			helpersv1.ImageIDMetadataKey:  "docker.io/library/nginx@sha256:2834",
			helpersv1.ImageTagMetadataKey: "nginx:1.21",
			helpersv1.StatusMetadataKey:   "ready",
		}},
		Spec: storagev1beta1.SBOMSyftSpec{Syft: storagev1beta1.SyftDocument{
			Distro: storagev1beta1.LinuxRelease{ID: "debian", VersionID: "11"},
			Artifacts: []storagev1beta1.SyftPackage{
				sbomPackage("zlib1g", "1:1.2.11", "deb", storagev1beta1.License{Value: "Zlib", SPDXExpression: "Zlib"}),
				sbomPackage("openssl", "1.1.1n", "deb",
					storagev1beta1.License{Value: "OpenSSL"},
					storagev1beta1.License{Value: "OpenSSL"}),
				sbomPackage("libssl1.1", "1.1.1n", "deb"),
				// Same package found in a second place: listed once.
				sbomPackage("libssl1.1", "1.1.1n", "deb"),
				sbomPackage("express", "4.17.1", "npm", storagev1beta1.License{Value: "MIT", SPDXExpression: "MIT"}),
			},
		}},
	}
	empty := &storagev1beta1.SBOMSyft{ObjectMeta: metav1.ObjectMeta{Name: "scratch", Namespace: "kubescape"}}
	tooLarge := &storagev1beta1.SBOMSyft{ObjectMeta: metav1.ObjectMeta{Name: "huge", Namespace: "kubescape", Annotations: map[string]string{
		helpersv1.StatusMetadataKey: helpersv1.TooLarge,
	}}}
	other := &storagev1beta1.SBOMSyft{ObjectMeta: metav1.ObjectMeta{Name: "redis-7", Namespace: "other"}}
	return &KubescapeMcpserver{ksClient: storagefake.NewClientset(sbom, empty, tooLarge, other).SpdxV1beta1()}
}

func callSBOMPackages(t *testing.T, ks *KubescapeMcpserver, args map[string]any) sbomPackageListResponse {
	t.Helper()
	result, err := ks.CallTool(context.Background(), "list_sbom_packages", args)
	require.NoError(t, err)
	require.False(t, result.IsError, toolResultText(t, result))
	var resp sbomPackageListResponse
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &resp))
	return resp
}

func packageNames(resp sbomPackageListResponse) []string {
	names := []string{}
	for _, p := range resp.Packages {
		names = append(names, p.Name)
	}
	return names
}

func TestListSBOMPackages_DefaultsAndOrder(t *testing.T) {
	resp := callSBOMPackages(t, sbomListServer(t), map[string]any{"sbom_name": "nginx-1.21"})
	assert.Equal(t, "nginx-1.21", resp.SBOMName)
	assert.Equal(t, "ready", resp.Status)
	assert.Equal(t, "debian 11", resp.Distro)
	assert.Equal(t, 4, resp.Total, "the duplicate libssl1.1 is listed once")
	assert.Equal(t, 4, resp.Returned)
	assert.False(t, resp.Truncated)
	assert.Nil(t, resp.NextOffset)
	assert.Equal(t, []string{"express", "libssl1.1", "openssl", "zlib1g"}, packageNames(resp))

	zlib := resp.Packages[3]
	assert.Equal(t, sbomPackageEntry{Name: "zlib1g", Version: "1:1.2.11", Type: "deb", PURL: "pkg:deb/zlib1g@1:1.2.11", Licenses: []string{"Zlib"}}, zlib)
	assert.Equal(t, []string{"OpenSSL"}, resp.Packages[2].Licenses, "repeated licenses are listed once; the value is used when there is no SPDX expression")
	assert.Equal(t, []string{}, resp.Packages[1].Licenses)
}

func TestListSBOMPackages_LeavesOutLocations(t *testing.T) {
	result, err := sbomListServer(t).CallTool(context.Background(), "list_sbom_packages", map[string]any{"sbom_name": "nginx-1.21"})
	require.NoError(t, err)
	text := toolResultText(t, result)
	assert.NotContains(t, text, "/var/lib/dpkg/status")
	assert.NotContains(t, text, "locations")
}

func TestListSBOMPackages_Filters(t *testing.T) {
	ks := sbomListServer(t)
	assert.Equal(t, []string{"libssl1.1", "openssl"}, packageNames(callSBOMPackages(t, ks, map[string]any{"sbom_name": "nginx-1.21", "name": "SSL"})),
		"name matches a case-insensitive substring")
	assert.Equal(t, []string{"express"}, packageNames(callSBOMPackages(t, ks, map[string]any{"sbom_name": "nginx-1.21", "package_type": "NPM"})))

	resp := callSBOMPackages(t, ks, map[string]any{"sbom_name": "nginx-1.21", "name": "ssl", "package_type": "npm"})
	assert.Equal(t, 0, resp.Total)
	assert.Equal(t, []sbomPackageEntry{}, resp.Packages)
}

func TestListSBOMPackages_Paging(t *testing.T) {
	ks := sbomListServer(t)
	first := callSBOMPackages(t, ks, map[string]any{"sbom_name": "nginx-1.21", "limit": float64(3)})
	assert.Equal(t, []string{"express", "libssl1.1", "openssl"}, packageNames(first))
	assert.Equal(t, 4, first.Total)
	assert.Equal(t, 3, first.Returned)
	assert.True(t, first.Truncated)
	require.NotNil(t, first.NextOffset)
	assert.Equal(t, 3, *first.NextOffset)

	second := callSBOMPackages(t, ks, map[string]any{"sbom_name": "nginx-1.21", "limit": float64(3), "offset": float64(*first.NextOffset)})
	assert.Equal(t, []string{"zlib1g"}, packageNames(second))
	assert.False(t, second.Truncated)
	assert.Nil(t, second.NextOffset)

	past := callSBOMPackages(t, ks, map[string]any{"sbom_name": "nginx-1.21", "offset": float64(10)})
	assert.Equal(t, 4, past.Total)
	assert.Equal(t, []sbomPackageEntry{}, past.Packages)
}

func TestListSBOMPackages_EmptySBOM(t *testing.T) {
	result, err := sbomListServer(t).CallTool(context.Background(), "list_sbom_packages", map[string]any{"sbom_name": "scratch"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"sbom_name":"scratch","total":0,"returned":0,"truncated":false,"packages":[]}`, toolResultText(t, result))
}

func TestListSBOMPackages_TooLargeSBOMKeepsStatus(t *testing.T) {
	result, err := sbomListServer(t).CallTool(context.Background(), "list_sbom_packages", map[string]any{"sbom_name": "huge"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"sbom_name":"huge","status":"`+helpersv1.TooLarge+`","total":0,"returned":0,"truncated":false,"packages":[]}`, toolResultText(t, result))
}

func TestListSBOMPackages_InvalidArguments(t *testing.T) {
	ks := sbomListServer(t)
	for _, tt := range []struct {
		name string
		args map[string]any
		want string
	}{
		{name: "missing sbom_name", args: map[string]any{}, want: "sbom_name argument is required"},
		{name: "name type", args: map[string]any{"sbom_name": "nginx-1.21", "name": 7}, want: "name argument must be a string"},
		{name: "package_type type", args: map[string]any{"sbom_name": "nginx-1.21", "package_type": true}, want: "package_type argument must be a string"},
		{name: "limit zero", args: map[string]any{"sbom_name": "nginx-1.21", "limit": float64(0)}, want: "limit must be between 1 and 500"},
		{name: "limit too large", args: map[string]any{"sbom_name": "nginx-1.21", "limit": float64(501)}, want: "limit must be between 1 and 500"},
		{name: "limit fraction", args: map[string]any{"sbom_name": "nginx-1.21", "limit": 1.5}, want: "limit argument must be an integer"},
		{name: "negative offset", args: map[string]any{"sbom_name": "nginx-1.21", "offset": float64(-1)}, want: "offset must not be negative"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ks.CallTool(context.Background(), "list_sbom_packages", tt.args)
			require.NoError(t, err)
			require.True(t, result.IsError)
			assert.Contains(t, toolResultText(t, result), tt.want)
		})
	}
}

func TestListSBOMPackages_NotFound(t *testing.T) {
	_, err := sbomListServer(t).CallTool(context.Background(), "list_sbom_packages", map[string]any{"sbom_name": "missing"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get SBOM")
}

func TestListSBOMs(t *testing.T) {
	ks := sbomListServer(t)
	call := func(args map[string]any) sbomListResponse {
		t.Helper()
		result, err := ks.CallTool(context.Background(), "list_sboms", args)
		require.NoError(t, err)
		require.False(t, result.IsError, toolResultText(t, result))
		var resp sbomListResponse
		require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &resp))
		return resp
	}

	all := call(map[string]any{})
	assert.Len(t, all.SBOMs, 4, "all namespaces by default")

	resp := call(map[string]any{"namespace": "kubescape"})
	require.Len(t, resp.SBOMs, 3)
	byName := map[string]sbomEntry{}
	for _, e := range resp.SBOMs {
		byName[e.SBOMName] = e
	}
	assert.Equal(t, sbomEntry{
		Namespace: "kubescape",
		SBOMName:  "nginx-1.21",
		ImageID:   "docker.io/library/nginx@sha256:2834",
		ImageTag:  "nginx:1.21",
		Status:    "ready",
	}, byName["nginx-1.21"])
	assert.Equal(t, sbomEntry{Namespace: "kubescape", SBOMName: "scratch"}, byName["scratch"])
	assert.Equal(t, helpersv1.TooLarge, byName["huge"].Status)

	result, err := ks.CallTool(context.Background(), "list_sboms", map[string]any{"namespace": "nobody"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"sboms":[]}`, toolResultText(t, result))

	result, err = ks.CallTool(context.Background(), "list_sboms", map[string]any{"continue": 3})
	require.NoError(t, err)
	require.True(t, result.IsError)
	assert.Contains(t, toolResultText(t, result), "continue argument must be a string")
}
