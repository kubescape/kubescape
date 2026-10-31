package attackpath

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/pkg/vulnexposure"
	storagev1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

// --- fixtures -------------------------------------------------------------
//
// Every fixture is a raw object run through CollectInputs, so BuildGraph is
// exercised against the real exposure, networkpolicy and rbacgraph engines
// and the real Phase 1 resolvers, not against hand-made Inputs.

func fxService(ns, name, typ string, selector map[string]any, ports ...any) workloadinterface.IMetadata {
	spec := map[string]any{"ports": ports}
	if typ != "" {
		spec["type"] = typ
	}
	if selector != nil {
		spec["selector"] = selector
	}
	return resource(map[string]any{
		"apiVersion": "v1", "kind": "Service",
		"metadata": map[string]any{"name": name, "namespace": ns},
		"spec":     spec,
	})
}

func fxServicePort(port int64, targetPort any) map[string]any {
	return map[string]any{"port": port, "targetPort": targetPort, "protocol": "TCP"}
}

func fxIngress(ns, name, host, svc string, port int64) workloadinterface.IMetadata {
	return resource(map[string]any{
		"apiVersion": "networking.k8s.io/v1", "kind": "Ingress",
		"metadata": map[string]any{"name": name, "namespace": ns},
		"spec": map[string]any{"rules": []any{map[string]any{
			"host": host,
			"http": map[string]any{"paths": []any{map[string]any{
				"path": "/", "pathType": "Prefix",
				"backend": map[string]any{"service": map[string]any{
					"name": svc, "port": map[string]any{"number": port},
				}},
			}}},
		}}},
	})
}

func fxWorkload(kind, apiVersion, ns, name, sa string, labels map[string]any, containerPorts []any) workloadinterface.IMetadata {
	container := map[string]any{"name": "app", "image": "img"}
	if len(containerPorts) > 0 {
		container["ports"] = containerPorts
	}
	podSpec := map[string]any{"containers": []any{container}}
	if sa != "" {
		podSpec["serviceAccountName"] = sa
	}
	return resource(map[string]any{
		"apiVersion": apiVersion, "kind": kind,
		"metadata": map[string]any{"name": name, "namespace": ns},
		"spec": map[string]any{"template": map[string]any{
			"metadata": map[string]any{"labels": labels},
			"spec":     podSpec,
		}},
	})
}

func fxDeploy(ns, name, sa string, labels map[string]any, containerPorts ...any) workloadinterface.IMetadata {
	return fxWorkload("Deployment", "apps/v1", ns, name, sa, labels, containerPorts)
}

func fxJob(ns, name, sa string, labels map[string]any) workloadinterface.IMetadata {
	return fxWorkload("Job", "batch/v1", ns, name, sa, labels, nil)
}

func fxServiceAccount(ns, name string) workloadinterface.IMetadata {
	return resource(map[string]any{
		"apiVersion": "v1", "kind": "ServiceAccount",
		"metadata": map[string]any{"name": name, "namespace": ns},
	})
}

// fxClusterAdminRole is the cluster-admin ClusterRole every fxAdminBinding refers to.
func fxClusterAdminRole() workloadinterface.IMetadata {
	return resource(map[string]any{
		"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
		"metadata": map[string]any{"name": "cluster-admin"},
		"rules": []any{map[string]any{
			"apiGroups": []any{"*"}, "resources": []any{"*"}, "verbs": []any{"*"},
		}},
	})
}

func fxAdminBinding(bindingName, saNamespace, sa string) workloadinterface.IMetadata {
	return resource(map[string]any{
		"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
		"metadata": map[string]any{"name": bindingName},
		"roleRef":  map[string]any{"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "cluster-admin"},
		"subjects": []any{map[string]any{"kind": "ServiceAccount", "name": sa, "namespace": saNamespace}},
	})
}

// fxIngressPolicy isolates the pods labelled selected for ingress and admits
// only port/TCP, from the pods labelled from (or from any source when from is nil).
func fxIngressPolicy(ns, name string, selected, from map[string]any, port int64) workloadinterface.IMetadata {
	rule := map[string]any{"ports": []any{map[string]any{"protocol": "TCP", "port": port}}}
	if from != nil {
		rule["from"] = []any{map[string]any{"podSelector": map[string]any{"matchLabels": from}}}
	}
	return resource(map[string]any{
		"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
		"metadata": map[string]any{"name": name, "namespace": ns},
		"spec": map[string]any{
			"podSelector": map[string]any{"matchLabels": selected},
			"policyTypes": []any{"Ingress"},
			"ingress":     []any{rule},
		},
	})
}

func fxVuln(id, severity string, fixed bool) storagev1beta1.Vulnerability {
	v := storagev1beta1.Vulnerability{
		VulnerabilityMetadata: storagev1beta1.VulnerabilityMetadata{ID: id, Severity: severity},
	}
	if fixed {
		v.Fix = storagev1beta1.Fix{Versions: []string{"1.2.4"}, State: "fixed"}
	}
	return v
}

// fxShop is the baseline cluster: shop.example.com -> Ingress -> Service
// shop/web (80 -> targetPort) -> Deployment shop/web -> ServiceAccount
// shop/web-sa, which is bound to cluster-admin. An ingress controller
// Deployment shop/ingress exists so tests can name it in IngressControllers.
func fxShop(targetPort any, containerPorts []any, extra ...workloadinterface.IMetadata) []workloadinterface.IMetadata {
	items := []workloadinterface.IMetadata{
		fxService("shop", "web", "", map[string]any{"app": "web"}, fxServicePort(80, targetPort)),
		fxIngress("shop", "web-ing", "shop.example.com", "web", 80),
		fxDeploy("shop", "web", "web-sa", map[string]any{"app": "web"}, containerPorts...),
		fxDeploy("shop", "ingress", "ingress-sa", map[string]any{"app": "ingress-controller"}),
		fxServiceAccount("shop", "web-sa"),
		fxServiceAccount("shop", "ingress-sa"),
		fxClusterAdminRole(),
		fxAdminBinding("web-admin", "shop", "web-sa"),
	}
	return append(items, extra...)
}

func fxBuild(items []workloadinterface.IMetadata, opts BuildOptions) (*Graph, SearchResult) {
	res := makeResources(items...)
	g := BuildGraph(res, CollectInputs(res), opts)
	return g, FindPaths(g, SearchOptions{})
}

var fxShopWeb = WorkloadRef{Namespace: "shop", Kind: "Deployment", Name: "web"}

// --- tests ----------------------------------------------------------------

func TestBuildGraph_EmptyInputsProducesOnlyStaticNodes(t *testing.T) {
	g := BuildGraph(makeResources(), Inputs{}, BuildOptions{})
	if _, ok := g.Nodes[fxInternet]; !ok {
		t.Error("expected Internet node always present")
	}
	if _, ok := g.Nodes[fxAdmin]; !ok {
		t.Error("expected ClusterAdmin node always present")
	}
	if len(g.Edges) != 0 {
		t.Errorf("expected no edges, got %v", g.Edges)
	}
}

func TestBuildGraph_NoExposedServiceMeansNoInternetEdge(t *testing.T) {
	items := []workloadinterface.IMetadata{
		fxService("prod", "internal", "", map[string]any{"app": "api"}, fxServicePort(80, 8080)),
		fxDeploy("prod", "api", "api-sa", map[string]any{"app": "api"}),
	}
	g, r := fxBuild(items, BuildOptions{})
	if edges := g.Edges[fxInternet]; len(edges) != 0 {
		t.Errorf("expected no Internet edges for an unexposed Service, got %v", edges)
	}
	if len(r.Paths) != 0 {
		t.Errorf("expected no paths, got %d", len(r.Paths))
	}
}

// The end-to-end case the previous builder tests never built: an Ingress-exposed
// Service whose backend runs as a cluster-admin ServiceAccount.
func TestBuildGraph_ExposedServiceReachesClusterAdmin(t *testing.T) {
	_, r := fxBuild(fxShop(8080, nil), BuildOptions{})
	if len(r.Paths) != 1 {
		t.Fatalf("expected 1 path, got %d (%+v)", len(r.Paths), r)
	}
	want := []NodeID{
		fxInternet,
		"Service:shop/web",
		"Workload:shop/Deployment/web",
		"ServiceAccount:shop/web-sa",
		fxAdmin,
	}
	p := r.Paths[0]
	if got := fxPathIDs(p); !reflect.DeepEqual(got, want) {
		t.Fatalf("path = %v, want %v", got, want)
	}
	if !p.Certain {
		t.Errorf("a path through an Ingress and an un-isolated backend is certain: %+v", p.Edges)
	}
	if r.Incomplete || r.HasVulnerabilityData {
		t.Errorf("unexpected diagnostics: %+v", r)
	}
	if !strings.Contains(p.Edges[0].Evidence, "shop/web-ing") || !strings.Contains(p.Edges[0].Evidence, "shop.example.com") {
		t.Errorf("exposure evidence should name the Ingress and host, got %q", p.Edges[0].Evidence)
	}
}

// A CVE is not a hop on the way to cluster-admin; it must still change the
// score of the path that runs through the vulnerable workload.
func TestBuildGraph_CVEsOnTraversedWorkloadChangeDefaultPathScore(t *testing.T) {
	_, base := fxBuild(fxShop(8080, nil), BuildOptions{})
	if len(base.Paths) != 1 {
		t.Fatalf("expected 1 base path, got %d", len(base.Paths))
	}

	vulns := map[vulnexposure.Workload][]storagev1beta1.Vulnerability{
		{Namespace: "shop", Kind: "Deployment", Name: "web"}: {
			fxVuln("CVE-2026-0001", "Critical", true),
			fxVuln("CVE-2026-0002", "Low", false), // below the default High threshold
		},
	}
	g, r := fxBuild(fxShop(8080, nil), BuildOptions{VulnsByWorkload: vulns})
	if len(r.Paths) != 1 {
		t.Fatalf("expected 1 path, got %d", len(r.Paths))
	}
	p := r.Paths[0]
	if p.CVESeverity != "Critical" || !p.CVEFixAvailable {
		t.Errorf("CVE factors missing from the path: %+v", p)
	}
	if got, want := p.Score-base.Paths[0].Score, 4.5; got != want {
		t.Errorf("a fixable Critical CVE should add %v points, added %v", want, got)
	}
	if !r.HasVulnerabilityData {
		t.Error("HasVulnerabilityData should be set when CVE data was supplied")
	}
	node := g.Nodes[workloadNodeID(fxShopWeb)]
	if len(node.Vulnerabilities) != 1 || node.Vulnerabilities[0].ID != "CVE-2026-0001" {
		t.Errorf("only CVEs at or above MinCVESeverity belong on the node, got %+v", node.Vulnerabilities)
	}
}

func TestBuildGraph_MinCVESeverityFiltersWorkloadCVEs(t *testing.T) {
	vulns := map[vulnexposure.Workload][]storagev1beta1.Vulnerability{
		{Namespace: "shop", Kind: "Deployment", Name: "web"}: {fxVuln("CVE-2026-0003", "Medium", false)},
	}
	_, r := fxBuild(fxShop(8080, nil), BuildOptions{VulnsByWorkload: vulns})
	if len(r.Paths) != 1 || r.Paths[0].CVESeverity != "" {
		t.Errorf("a Medium CVE is below the default High threshold: %+v", r.Paths)
	}
	_, r = fxBuild(fxShop(8080, nil), BuildOptions{VulnsByWorkload: vulns, MinCVESeverity: vulnexposure.SeverityMedium})
	if len(r.Paths) != 1 || r.Paths[0].CVESeverity != "Medium" {
		t.Errorf("with MinCVESeverity=Medium the CVE must count: %+v", r.Paths)
	}
}

// A public Deployment and a privileged Job that share a namespace and name must
// stay two nodes; collapsing them fabricates a path through the Job's identity.
func TestBuildGraph_WorkloadIdentityIncludesKind(t *testing.T) {
	items := []workloadinterface.IMetadata{
		fxService("shop", "web", "", map[string]any{"app": "web"}, fxServicePort(80, 8080)),
		fxIngress("shop", "web-ing", "shop.example.com", "web", 80),
		fxDeploy("shop", "app", "plain-sa", map[string]any{"app": "web"}),
		fxJob("shop", "app", "admin-sa", map[string]any{"app": "batch"}),
		fxServiceAccount("shop", "plain-sa"),
		fxServiceAccount("shop", "admin-sa"),
		fxClusterAdminRole(),
		fxAdminBinding("admin", "shop", "admin-sa"),
	}
	res := makeResources(items...)
	g := BuildGraph(res, CollectInputs(res), BuildOptions{})

	deploy := workloadNodeID(WorkloadRef{Namespace: "shop", Kind: "Deployment", Name: "app"})
	job := workloadNodeID(WorkloadRef{Namespace: "shop", Kind: "Job", Name: "app"})
	if _, ok := g.Nodes[deploy]; !ok {
		t.Fatalf("missing node %s", deploy)
	}
	if _, ok := g.Nodes[job]; !ok {
		t.Fatalf("missing node %s", job)
	}

	if r := FindPaths(g, SearchOptions{}); len(r.Paths) != 0 {
		t.Errorf("the Internet only reaches the unprivileged Deployment; got a path through %v", fxPathIDs(r.Paths[0]))
	}
	// The internal Job is not behind any Service, but is still a valid source.
	r := FindPaths(g, SearchOptions{From: job})
	if len(r.Paths) != 1 {
		t.Fatalf("expected the Job to reach cluster-admin from a custom source, got %d paths", len(r.Paths))
	}
}

// N workloads sharing one ServiceAccount add one escalation edge, not N.
func TestBuildGraph_SharedServiceAccountHasOneEscalationEdge(t *testing.T) {
	items := fxShop(8080, nil,
		fxDeploy("shop", "web-canary", "web-sa", map[string]any{"app": "web"}),
	)
	g, r := fxBuild(items, BuildOptions{})
	if got := len(g.Edges["ServiceAccount:shop/web-sa"]); got != 1 {
		t.Errorf("expected exactly one SA -> cluster-admin edge, got %d", got)
	}
	// Two backends, so two genuinely different paths. Not four.
	if len(r.Paths) != 2 {
		t.Errorf("expected 2 paths (one per backend), got %d", len(r.Paths))
	}
}

func TestBuildGraph_LoadBalancerExposureIsUncertain(t *testing.T) {
	items := []workloadinterface.IMetadata{
		fxService("shop", "web", "LoadBalancer", map[string]any{"app": "web"}, fxServicePort(80, 8080)),
		fxDeploy("shop", "web", "web-sa", map[string]any{"app": "web"}),
		fxServiceAccount("shop", "web-sa"),
		fxClusterAdminRole(),
		fxAdminBinding("web-admin", "shop", "web-sa"),
	}
	_, r := fxBuild(items, BuildOptions{})
	if len(r.Paths) != 1 {
		t.Fatalf("expected 1 path, got %d", len(r.Paths))
	}
	if r.Paths[0].Certain {
		t.Error("LoadBalancer/NodePort exposure must not be promoted to a certain path in v1 (proposal §3.5)")
	}
	if r.UncertainEdgeCount == 0 {
		t.Error("the uncertain edges must be counted")
	}
}

func TestBuildGraph_ExposedSelectorlessServiceIsReportedSkipped(t *testing.T) {
	items := []workloadinterface.IMetadata{
		fxService("shop", "manual", "LoadBalancer", nil, fxServicePort(80, 8080)),
	}
	g, _ := fxBuild(items, BuildOptions{})
	if !slices.ContainsFunc(g.Skipped, func(s string) bool { return strings.Contains(s, "shop/manual") && strings.Contains(s, "no selector") }) {
		t.Errorf("a selector-less exposed Service must be reported as skipped, got %v", g.Skipped)
	}
}

// The network hop is evaluated against the actual source (the ingress
// controller) and the Service's actual target port.
func TestBuildGraph_NetworkHopEvaluatesSourceAndPort(t *testing.T) {
	controller := map[string]any{"app": "ingress-controller"}
	web := map[string]any{"app": "web"}
	ctrlRef := []WorkloadRef{{Namespace: "shop", Kind: "Deployment", Name: "ingress"}}
	httpPort := []any{map[string]any{"name": "http", "containerPort": int64(8080)}}

	cases := []struct {
		name          string
		targetPort    any
		containerPort []any
		policy        workloadinterface.IMetadata
		controllers   []WorkloadRef
		wantPath      bool
		wantCertain   bool
	}{
		{
			name:       "no policy: default allow is certain",
			targetPort: 8080, wantPath: true, wantCertain: true,
		},
		{
			name:       "controller allowed on the target port",
			targetPort: 8080, policy: fxIngressPolicy("shop", "np", web, controller, 8080),
			controllers: ctrlRef, wantPath: true, wantCertain: true,
		},
		{
			name:       "controller allowed only on another port: confirmed denied, no edge",
			targetPort: 8080, policy: fxIngressPolicy("shop", "np", web, controller, 9090),
			controllers: ctrlRef, wantPath: false,
		},
		{
			// Source breadth says "open", but not on the port the Service targets.
			name:       "any source on 9090, Service targets 8080: denied, no edge",
			targetPort: 8080, policy: fxIngressPolicy("shop", "np", web, nil, 9090),
			controllers: ctrlRef, wantPath: false,
		},
		{
			name:       "isolated and controller not identified: uncertain",
			targetPort: 8080, policy: fxIngressPolicy("shop", "np", web, controller, 8080),
			wantPath: true, wantCertain: false,
		},
		{
			name:       "isolated by any-source rule on the wrong port, controller not identified: uncertain",
			targetPort: 8080, policy: fxIngressPolicy("shop", "np", web, nil, 9090),
			wantPath: true, wantCertain: false,
		},
		{
			name:       "named targetPort resolved from the container spec",
			targetPort: "http", containerPort: httpPort, policy: fxIngressPolicy("shop", "np", web, controller, 8080),
			controllers: ctrlRef, wantPath: true, wantCertain: true,
		},
		{
			name:       "named targetPort that cannot be resolved: uncertain, not denied",
			targetPort: "missing", containerPort: httpPort, policy: fxIngressPolicy("shop", "np", web, controller, 8080),
			controllers: ctrlRef, wantPath: true, wantCertain: false,
		},
		{
			name:       "configured controller missing from the snapshot: a denial is unprovable",
			targetPort: 8080, policy: fxIngressPolicy("shop", "np", web, controller, 9090),
			controllers: []WorkloadRef{{Namespace: "shop", Kind: "Deployment", Name: "absent"}}, wantPath: true, wantCertain: false,
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			var extra []workloadinterface.IMetadata
			if tt.policy != nil {
				extra = append(extra, tt.policy)
			}
			_, r := fxBuild(fxShop(tt.targetPort, tt.containerPort, extra...), BuildOptions{IngressControllers: tt.controllers})
			if tt.wantPath != (len(r.Paths) > 0) {
				t.Fatalf("wantPath=%v, got %d paths (%+v)", tt.wantPath, len(r.Paths), r)
			}
			if tt.wantPath && r.Paths[0].Certain != tt.wantCertain {
				t.Errorf("path Certain = %v, want %v; edges: %+v", r.Paths[0].Certain, tt.wantCertain, r.Paths[0].Edges)
			}
		})
	}
}

// A LoadBalancer exposure next to an Ingress: the Ingress hop may be denied,
// but the LoadBalancer path cannot be refuted, so the edge stays, uncertain.
func TestBuildGraph_DeniedIngressHopKeepsEdgeWhenAlsoExposedDirectly(t *testing.T) {
	items := fxShop(8080, nil,
		fxIngressPolicy("shop", "np", map[string]any{"app": "web"}, map[string]any{"app": "ingress-controller"}, 9090),
	)
	items[0] = fxService("shop", "web", "LoadBalancer", map[string]any{"app": "web"}, fxServicePort(80, 8080))
	_, r := fxBuild(items, BuildOptions{IngressControllers: []WorkloadRef{{Namespace: "shop", Kind: "Deployment", Name: "ingress"}}})
	if len(r.Paths) == 0 {
		t.Fatal("the LoadBalancer path must survive a denied Ingress hop")
	}
	for _, p := range r.Paths {
		if p.Certain {
			t.Errorf("no path may be certain here: %+v", p.Edges)
		}
	}
}

func TestBuildGraph_TokenNotMountedHasNoRunsAsEdge(t *testing.T) {
	// automountServiceAccountToken: false and the ServiceAccount is collected,
	// so the resolver can prove no token is mounted (proposal §7).
	items := []workloadinterface.IMetadata{
		workloadWithSA("prod", "secure", "my-sa", boolPtr(false), nil),
		fxServiceAccount("prod", "my-sa"),
	}
	res := makeResources(items...)
	g := BuildGraph(res, CollectInputs(res), BuildOptions{})
	for _, e := range g.Edges[workloadNodeID(WorkloadRef{Namespace: "prod", Kind: "Deployment", Name: "secure"})] {
		if e.Kind == EdgeRunsAs {
			t.Error("expected no runs-as edge when automountServiceAccountToken=false")
		}
	}
}

func TestBuildGraph_TokenStateUnknownKeepsAnUncertainRunsAsEdge(t *testing.T) {
	// The ServiceAccount object is not in the snapshot and the pod does not say,
	// so whether a token is mounted cannot be established statically.
	items := []workloadinterface.IMetadata{workloadWithSA("prod", "web", "ghost-sa", nil, nil)}
	res := makeResources(items...)
	g := BuildGraph(res, CollectInputs(res), BuildOptions{})
	edges := g.Edges[workloadNodeID(WorkloadRef{Namespace: "prod", Kind: "Deployment", Name: "web"})]
	if len(edges) != 1 || edges[0].Kind != EdgeRunsAs || edges[0].Certain {
		t.Errorf("expected one uncertain runs-as edge, got %+v", edges)
	}
}

// An unavailable engine must surface in the result, whether or not any path
// was found, so an empty result is never read as "safe".
func TestBuildGraph_UnavailableEnginesAreReportedInTheSearchResult(t *testing.T) {
	inp := Inputs{
		NetworkPolicyUnavailable: true,
		RBACUnavailable:          true,
		Warnings:                 []string{"exposure/gateway: decode error"},
	}
	g := BuildGraph(makeResources(), inp, BuildOptions{})
	for _, want := range []string{
		"exposure/gateway: decode error",
		"exposure analysis unavailable",
		"NetworkPolicy evaluation unavailable",
		"RBAC evaluation unavailable",
	} {
		if !slices.ContainsFunc(g.Warnings, func(w string) bool { return strings.Contains(w, want) }) {
			t.Errorf("missing warning containing %q in %v", want, g.Warnings)
		}
	}
	r := FindPaths(g, SearchOptions{})
	if len(r.Paths) != 0 || !r.Incomplete || len(r.Warnings) != len(g.Warnings) {
		t.Errorf("a negative result must carry the warnings: %+v", r)
	}
}

func TestBuildGraph_OutputIsDeterministic(t *testing.T) {
	build := func() (*Graph, SearchResult) {
		return fxBuild(fxShop(8080, nil,
			fxDeploy("shop", "web-canary", "web-sa", map[string]any{"app": "web"}),
			fxDeploy("shop", "web-beta", "web-sa", map[string]any{"app": "web"}),
		), BuildOptions{})
	}
	g1, r1 := build()
	for range 10 {
		g2, r2 := build()
		if !reflect.DeepEqual(g1, g2) {
			t.Fatal("graph differs between runs")
		}
		if !reflect.DeepEqual(r1, r2) {
			t.Fatal("search result differs between runs")
		}
	}
}
