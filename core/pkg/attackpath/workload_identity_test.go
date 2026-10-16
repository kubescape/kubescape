package attackpath

import (
	"strings"
	"testing"

	"github.com/kubescape/kubescape/v4/core/pkg/vulnexposure"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func boolPtr(b bool) *bool { return &b }

func saIndex(sas ...corev1.ServiceAccount) *ServiceAccountIndex { return NewServiceAccountIndex(sas) }

func saWith(ns, name string, automount *bool) corev1.ServiceAccount {
	return corev1.ServiceAccount{
		ObjectMeta:                   metav1.ObjectMeta{Namespace: ns, Name: name},
		AutomountServiceAccountToken: automount,
	}
}

// deployment builds a Deployment whose pod spec is mutated by the caller.
func deployment(ns, name string, spec map[string]any) map[string]any {
	if _, ok := spec["containers"]; !ok {
		spec["containers"] = []any{map[string]any{"name": "app", "image": "app:1"}}
	}
	return map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"namespace": ns, "name": name},
		"spec":       map[string]any{"template": map[string]any{"spec": spec}},
	}
}

func tokenVolume(name string, paths ...string) map[string]any {
	var sources []any
	for _, p := range paths {
		sources = append(sources, map[string]any{"serviceAccountToken": map[string]any{"path": p, "expirationSeconds": int64(3600)}})
	}
	return map[string]any{"name": name, "projected": map[string]any{"sources": sources}}
}

func containerMounting(mounts ...map[string]any) map[string]any {
	var vm []any
	for _, m := range mounts {
		vm = append(vm, m)
	}
	return map[string]any{"name": "app", "image": "app:1", "volumeMounts": vm}
}

func mount(volume, mountPath string, extra ...string) map[string]any {
	m := map[string]any{"name": volume, "mountPath": mountPath}
	if len(extra) == 2 {
		m[extra[0]] = extra[1]
	}
	return m
}

var shopWeb = vulnexposure.Workload{Namespace: "shop", Kind: "Deployment", Name: "web"}

func TestResolveServiceAccount_Identity(t *testing.T) {
	sas := saIndex(saWith("shop", "default", nil), saWith("shop", "worker", nil))

	cases := []struct {
		name       string
		spec       map[string]any
		wantName   string
		wantOrigin ServiceAccountOrigin
		wantReason string
	}{
		{"explicit", map[string]any{"serviceAccountName": "worker"}, "worker", OriginExplicit, ""},
		{"omitted is defaulted", map[string]any{}, "default", OriginDefaulted, ""},
		{"empty is defaulted", map[string]any{"serviceAccountName": ""}, "default", OriginDefaulted, ""},
		{"explicit default is not defaulted", map[string]any{"serviceAccountName": "default"}, "default", OriginExplicit, ""},
		{"deprecated field alone", map[string]any{"serviceAccount": "worker"}, "worker", OriginExplicit, ""},
		{"deprecated field agreeing", map[string]any{"serviceAccountName": "worker", "serviceAccount": "worker"}, "worker", OriginExplicit, ""},
		{"deprecated field conflicting", map[string]any{"serviceAccountName": "worker", "serviceAccount": "other"}, "", "", "conflicts"},
		{"non-string name", map[string]any{"serviceAccountName": int64(3)}, "", "", "not a string"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ResolveServiceAccount(shopWeb, deployment("shop", "web", c.spec), sas)
			if c.wantReason != "" {
				if got.Resolved || !strings.Contains(got.Reason, c.wantReason) {
					t.Fatalf("got %+v, want unresolved with %q", got, c.wantReason)
				}
				return
			}
			if !got.Resolved || got.Name != c.wantName || got.Origin != c.wantOrigin || got.Namespace != "shop" {
				t.Errorf("got %+v, want %s/%s (%s)", got, "shop", c.wantName, c.wantOrigin)
			}
		})
	}
}

func TestResolveServiceAccount_UnresolvedWorkloads(t *testing.T) {
	sas := saIndex()
	good := deployment("shop", "web", map[string]any{})

	cases := []struct {
		name string
		w    vulnexposure.Workload
		obj  map[string]any
		want string
	}{
		{"unsupported kind", vulnexposure.Workload{Namespace: "shop", Kind: "Rollout", Name: "web"}, good, "not a supported workload kind"},
		{"absent object", shopWeb, nil, "not found in the collected resources"},
		{"other namespace", vulnexposure.Workload{Namespace: "prod", Kind: "Deployment", Name: "web"}, good, "namespace"},
		{"other name", vulnexposure.Workload{Namespace: "shop", Kind: "Deployment", Name: "api"}, good, "name"},
		{"other kind", vulnexposure.Workload{Namespace: "shop", Kind: "StatefulSet", Name: "web"}, good, "kind"},
		{"no pod spec", shopWeb, map[string]any{"kind": "Deployment", "metadata": map[string]any{"namespace": "shop", "name": "web"}}, "no readable pod spec"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ResolveServiceAccount(c.w, c.obj, sas)
			if got.Resolved || !strings.Contains(got.Reason, c.want) {
				t.Errorf("got %+v, want unresolved containing %q", got, c.want)
			}
		})
	}
}

func TestResolveServiceAccount_SupportedKindsReadTheirOwnPodSpecPath(t *testing.T) {
	sas := saIndex(saWith("shop", "worker", nil))
	podSpec := map[string]any{"serviceAccountName": "worker", "containers": []any{map[string]any{"name": "c"}}}
	objs := map[string]map[string]any{
		"Pod": {"kind": "Pod", "metadata": map[string]any{"namespace": "shop", "name": "x"}, "spec": podSpec},
		"CronJob": {"kind": "CronJob", "metadata": map[string]any{"namespace": "shop", "name": "x"},
			"spec": map[string]any{"jobTemplate": map[string]any{"spec": map[string]any{"template": map[string]any{"spec": podSpec}}}}},
	}
	for _, kind := range []string{"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"} {
		objs[kind] = map[string]any{"kind": kind, "metadata": map[string]any{"namespace": "shop", "name": "x"},
			"spec": map[string]any{"template": map[string]any{"spec": podSpec}}}
	}
	for kind, obj := range objs {
		got := ResolveServiceAccount(vulnexposure.Workload{Namespace: "shop", Kind: kind, Name: "x"}, obj, sas)
		if !got.Resolved || got.Name != "worker" {
			t.Errorf("%s: got %+v, want worker", kind, got)
		}
	}
}

func TestResolveServiceAccount_AutomountLevels(t *testing.T) {
	cases := []struct {
		name string
		spec map[string]any
		sas  *ServiceAccountIndex
		want TokenState
	}{
		{"default: both unset", map[string]any{}, saIndex(saWith("shop", "default", nil)), TokenMounted},
		{"service account disables", map[string]any{}, saIndex(saWith("shop", "default", boolPtr(false))), TokenNotMounted},
		{"service account enables", map[string]any{}, saIndex(saWith("shop", "default", boolPtr(true))), TokenMounted},
		{"pod disables over service account", map[string]any{"automountServiceAccountToken": false}, saIndex(saWith("shop", "default", boolPtr(true))), TokenNotMounted},
		{"pod enables over service account", map[string]any{"automountServiceAccountToken": true}, saIndex(saWith("shop", "default", boolPtr(false))), TokenMounted},
		{"pod null falls through to service account", map[string]any{"automountServiceAccountToken": nil}, saIndex(saWith("shop", "default", boolPtr(false))), TokenNotMounted},
		// Without the ServiceAccount object its own setting is not known.
		{"unset and service account not collected", map[string]any{}, saIndex(), TokenUnknown},
		{"pod decides without the service account object", map[string]any{"automountServiceAccountToken": false}, saIndex(), TokenNotMounted},
		{"pod enables without the service account object", map[string]any{"automountServiceAccountToken": true}, saIndex(), TokenMounted},
		{"non-boolean pod setting", map[string]any{"automountServiceAccountToken": "false"}, saIndex(saWith("shop", "default", nil)), TokenUnknown},
		// A ServiceAccount in another namespace is not this one.
		{"same name in another namespace", map[string]any{}, saIndex(saWith("prod", "default", boolPtr(false))), TokenUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ResolveServiceAccount(shopWeb, deployment("shop", "web", c.spec), c.sas)
			if got.Token != c.want {
				t.Errorf("Token = %q (%s), want %q", got.Token, got.TokenReason, c.want)
			}
		})
	}
}

func TestResolveServiceAccount_TokenPathOccupancy(t *testing.T) {
	sas := saIndex(saWith("shop", "default", nil))
	occupied := containerMounting(mount("own", serviceAccountTokenMountPath))
	free := map[string]any{"name": "sidecar"}

	cases := []struct {
		name string
		spec map[string]any
		want TokenState
	}{
		{"every container occupies the path", map[string]any{"containers": []any{occupied}}, TokenNotMounted},
		{"one container is left without it", map[string]any{"containers": []any{occupied, free}}, TokenMounted},
		{"an init container is left without it", map[string]any{"containers": []any{occupied}, "initContainers": []any{free}}, TokenMounted},
		{"init container occupies too", map[string]any{"containers": []any{occupied}, "initContainers": []any{occupied}}, TokenNotMounted},
		{"no containers", map[string]any{"containers": []any{}}, TokenUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ResolveServiceAccount(shopWeb, deployment("shop", "web", c.spec), sas)
			if got.Token != c.want {
				t.Errorf("Token = %q (%s), want %q", got.Token, got.TokenReason, c.want)
			}
		})
	}
}

func TestResolveServiceAccount_ProjectedTokenSubPaths(t *testing.T) {
	// Automount is off so the projected volume is the only route.
	off := map[string]any{"automountServiceAccountToken": false}
	sas := saIndex(saWith("shop", "default", nil))

	run := func(vol map[string]any, m map[string]any) tokenResult {
		spec := map[string]any{
			"automountServiceAccountToken": off["automountServiceAccountToken"],
			"volumes":                      []any{vol},
			"containers":                   []any{containerMounting(m)},
		}
		r := ResolveServiceAccount(shopWeb, deployment("shop", "web", spec), sas)
		return tokenResult{r.Token, r.TokenReason}
	}
	tok := tokenVolume("tok", "token")
	nested := tokenVolume("tok", "dir/token")

	cases := []struct {
		name string
		vol  map[string]any
		m    map[string]any
		want TokenState
	}{
		{"whole volume", tok, mount("tok", "/t"), TokenMounted},
		{"subPath names the token", tok, mount("tok", "/t", "subPath", "token"), TokenMounted},
		{"subPath ./token", tok, mount("tok", "/t", "subPath", "./token"), TokenMounted},
		{"subPath dot is the whole volume", tok, mount("tok", "/t", "subPath", "."), TokenMounted},
		{"subPath dot slash", tok, mount("tok", "/t", "subPath", "./"), TokenMounted},
		{"subPath is a parent directory", nested, mount("tok", "/t", "subPath", "dir"), TokenMounted},
		{"subPath is a parent with trailing slash", nested, mount("tok", "/t", "subPath", "dir/"), TokenMounted},
		{"subPath names a sibling", tok, mount("tok", "/t", "subPath", "namespace"), TokenNotMounted},
		{"subPath names a sibling in a directory", nested, mount("tok", "/t", "subPath", "dir/ca.crt"), TokenNotMounted},
		{"subPath is a prefix of the name, not an ancestor", tok, mount("tok", "/t", "subPath", "tok"), TokenNotMounted},
		// AtomicWriter aliases: "..data" is the volume root.
		{"subPath ..data is the whole volume", tok, mount("tok", "/t", "subPath", "..data"), TokenMounted},
		{"subPath ..data/token", tok, mount("tok", "/t", "subPath", "..data/token"), TokenMounted},
		{"subPath ..data/dir/token", nested, mount("tok", "/t", "subPath", "..data/dir/token"), TokenMounted},
		{"subPath ..data/dir", nested, mount("tok", "/t", "subPath", "..data/dir"), TokenMounted},
		{"literal subPathExpr ..data/token", tok, mount("tok", "/t", "subPathExpr", "..data/token"), TokenMounted},
		{"subPath ..data/ sibling", tok, mount("tok", "/t", "subPath", "..data/namespace"), TokenNotMounted},
		{"subPath ..data/ sibling in a directory", nested, mount("tok", "/t", "subPath", "..data/dir/ca.crt"), TokenNotMounted},
		{"subPath is the timestamped directory", tok, mount("tok", "/t", "subPath", "..2026_10_16_08_00_00.123456789/token"), TokenUnknown},
		{"subPath escapes the volume", tok, mount("tok", "/t", "subPath", "../token"), TokenUnknown},
		{"subPath is absolute", tok, mount("tok", "/t", "subPath", "/token"), TokenUnknown},
		// A literal subPathExpr is a path like any other.
		{"literal subPathExpr naming a sibling", tok, mount("tok", "/t", "subPathExpr", "namespace"), TokenNotMounted},
		{"literal subPathExpr naming the token", tok, mount("tok", "/t", "subPathExpr", "token"), TokenMounted},
		// One that depends on the environment cannot be established.
		{"variable subPathExpr", tok, mount("tok", "/t", "subPathExpr", "$(POD_NAME)"), TokenUnknown},
		{"variable subPathExpr in a path", tok, mount("tok", "/t", "subPathExpr", "dir/$(POD_NAME)"), TokenUnknown},
		{"subPath and subPathExpr together", tok, map[string]any{"name": "tok", "mountPath": "/t", "subPath": "token", "subPathExpr": "token"}, TokenUnknown},
		{"volume that is not mounted", tok, mount("other", "/t"), TokenNotMounted},
		{"token path not given", map[string]any{"name": "tok", "projected": map[string]any{"sources": []any{map[string]any{"serviceAccountToken": map[string]any{}}}}}, mount("tok", "/t", "subPath", "x"), TokenUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := run(c.vol, c.m); got.token != c.want {
				t.Errorf("Token = %q (%s), want %q", got.token, got.reason, c.want)
			}
		})
	}
}

type tokenResult struct {
	token  TokenState
	reason string
}

func TestResolveServiceAccount_UnknownIsNeverNotMounted(t *testing.T) {
	// An unknown automatic token must not be hidden by a closed projected
	// route, and an unknown projected route must not be hidden by a closed
	// automatic one.
	tok := tokenVolume("tok", "token")
	dynamic := mount("tok", "/t", "subPathExpr", "$(X)")

	unknownAuto := deployment("shop", "web", map[string]any{
		"volumes":    []any{tok},
		"containers": []any{containerMounting(mount("tok", "/t", "subPath", "namespace"))},
	})
	if got := ResolveServiceAccount(shopWeb, unknownAuto, saIndex()); got.Token != TokenUnknown {
		t.Errorf("unknown automatic token + closed projected = %q, want unknown", got.Token)
	}

	unknownVol := deployment("shop", "web", map[string]any{
		"automountServiceAccountToken": false,
		"volumes":                      []any{tok},
		"containers":                   []any{containerMounting(dynamic)},
	})
	if got := ResolveServiceAccount(shopWeb, unknownVol, saIndex()); got.Token != TokenUnknown {
		t.Errorf("closed automatic + unknown projected = %q, want unknown", got.Token)
	}

	// A definite exposure outweighs an unknown one.
	mountedWins := deployment("shop", "web", map[string]any{
		"automountServiceAccountToken": false,
		"volumes":                      []any{tok},
		"containers":                   []any{containerMounting(dynamic, mount("tok", "/u"))},
	})
	if got := ResolveServiceAccount(shopWeb, mountedWins, saIndex()); got.Token != TokenMounted {
		t.Errorf("definite + unknown exposure = %q, want mounted", got.Token)
	}
}

func TestResolveServiceAccount_MalformedSpecIsUnknownNotNotMounted(t *testing.T) {
	sas := saIndex(saWith("shop", "default", boolPtr(false)))
	cases := map[string]map[string]any{
		"volumes not a list":    {"automountServiceAccountToken": false, "volumes": "oops"},
		"volume not an object":  {"automountServiceAccountToken": false, "volumes": []any{"oops"}},
		"containers not a list": {"automountServiceAccountToken": false, "containers": "oops"},
	}
	for name, spec := range cases {
		t.Run(name, func(t *testing.T) {
			got := ResolveServiceAccount(shopWeb, deployment("shop", "web", spec), sas)
			if !got.Resolved || got.Token != TokenUnknown {
				t.Errorf("got %+v, want resolved with unknown token", got)
			}
		})
	}
}

func TestResolveWorkloadIdentities_AdaptsAndKeepsUnresolvedApart(t *testing.T) {
	a := vulnexposure.Workload{Namespace: "shop", Kind: "Deployment", Name: "a"}
	missing := vulnexposure.Workload{Namespace: "shop", Kind: "Deployment", Name: "missing"}
	unsupported := vulnexposure.Workload{Namespace: "shop", Kind: "Rollout", Name: "r"}
	objs := map[vulnexposure.Workload]map[string]any{
		a: deployment("shop", "a", map[string]any{"serviceAccountName": "worker", "automountServiceAccountToken": false}),
	}

	ids, unresolved := ResolveWorkloadIdentities(objs, []vulnexposure.Workload{a, missing, unsupported}, saIndex(saWith("shop", "worker", nil)))

	got, ok := ids[a]
	if !ok || got.ServiceAccountName != "worker" || got.Origin != OriginExplicit || got.Token != TokenNotMounted || got.Namespace != "shop" || got.TokenReason == "" {
		t.Errorf("identity for a = %+v, ok %v", got, ok)
	}
	if len(ids) != 1 || len(unresolved) != 2 || unresolved[missing] == "" || unresolved[unsupported] == "" {
		t.Errorf("identities %d, unresolved %v, want 1 resolved and 2 unresolved with reasons", len(ids), unresolved)
	}
}

func TestResolveServiceAccount_EphemeralContainerCanMountAnExistingTokenVolume(t *testing.T) {
	// Automounting is off and no regular container mounts the projected
	// token, but an ephemeral container (live Pods only) does.
	spec := map[string]any{
		"automountServiceAccountToken": false,
		"volumes":                      []any{tokenVolume("tok", "token")},
		"containers":                   []any{map[string]any{"name": "app"}},
		"ephemeralContainers":          []any{containerMounting(mount("tok", "/t"))},
	}
	pod := map[string]any{"kind": "Pod", "metadata": map[string]any{"namespace": "shop", "name": "p"}, "spec": spec}

	got := ResolveServiceAccount(vulnexposure.Workload{Namespace: "shop", Kind: "Pod", Name: "p"}, pod, saIndex(saWith("shop", "default", nil)))
	if got.Token != TokenMounted {
		t.Errorf("Token = %q (%s), want mounted", got.Token, got.TokenReason)
	}

	// An ephemeral container is not given the automatic token, so one that
	// mounts nothing does not change a closed result.
	spec["ephemeralContainers"] = []any{map[string]any{"name": "debug"}}
	got = ResolveServiceAccount(vulnexposure.Workload{Namespace: "shop", Kind: "Pod", Name: "p"}, pod, saIndex(saWith("shop", "default", nil)))
	if got.Token != TokenNotMounted {
		t.Errorf("Token = %q (%s), want not-mounted", got.Token, got.TokenReason)
	}

	spec["ephemeralContainers"] = "oops"
	got = ResolveServiceAccount(vulnexposure.Workload{Namespace: "shop", Kind: "Pod", Name: "p"}, pod, saIndex(saWith("shop", "default", nil)))
	if got.Token != TokenUnknown {
		t.Errorf("Token = %q, want unknown for unreadable ephemeral containers", got.Token)
	}
}
