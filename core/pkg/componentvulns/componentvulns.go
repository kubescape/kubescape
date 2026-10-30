// Package componentvulns matches the cluster component inventory against the
// vulnerability database and emits one external resource per component, so
// posture controls can evaluate the API server, kubelet and container runtime
// the same way they evaluate any other resource. Anything that cannot be
// assessed is returned as a gap instead of a resource, because a resource
// without findings would be evaluated as passed.
package componentvulns

import (
	"cmp"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/pkg/clustercomponents"
	"github.com/kubescape/kubescape/v4/core/pkg/k8scveindex"
)

const (
	Group      = "componentvulns.kubescape.cloud"
	Version    = "v1beta0"
	APIVersion = Group + "/" + Version

	// ClusterSelector is the gap selector for cluster-scoped kinds.
	ClusterSelector = "cluster"

	kubernetesModule = "k8s.io/kubernetes"
	criOModule       = "github.com/cri-o/cri-o"
	containerdModule = "github.com/containerd/containerd"
)

type Kind string

const (
	APIServerVulnerabilities        Kind = "APIServerVulnerabilities"
	KubeletVulnerabilities          Kind = "KubeletVulnerabilities"
	ContainerRuntimeVulnerabilities Kind = "ContainerRuntimeVulnerabilities"
)

// Matcher is satisfied by imagescan.Service.
type Matcher interface {
	MatchPackages(packages []pkg.Package, pkgContext pkg.Context, vulnerabilityExceptions, severityExceptions []string) (match.Matches, []match.IgnoredMatch, error)
}

type Options struct {
	// Kinds are the kinds backing a selected control; nothing else is built.
	Kinds []Kind
	// Index attributes Kubernetes CVEs to components. Without it no Kubernetes
	// CVE can be attributed, so every Kubernetes component becomes a gap.
	Index       *k8scveindex.Index
	IndexMaxAge time.Duration
	DBBuilt     time.Time
	Now         time.Time
}

type Gap struct {
	Kind     Kind
	Selector string
	Reason   string
}

type Vulnerability struct {
	ID             string   `json:"id"`
	Aliases        []string `json:"aliases,omitempty"`
	Severity       string   `json:"severity"`
	FixState       string   `json:"fixState"`
	FixedIn        []string `json:"fixedIn,omitempty"`
	KnownExploited bool     `json:"knownExploited"`
	EPSS           *float64 `json:"epss,omitempty"`
}

type Result struct {
	Resources []workloadinterface.IMetadata
	Gaps      []Gap
}

type target struct {
	kind     Kind
	name     string
	os       string
	version  clustercomponents.ComponentVersion
	pkgID    pkg.ID
	selector string
}

// Build looks up every distinct component version once and returns the
// resources and gaps for the requested kinds. An error means nothing could be
// matched and every requested kind is unassessed.
func Build(inv clustercomponents.Inventory, m Matcher, opts Options) (Result, error) {
	var res Result
	if len(opts.Kinds) == 0 {
		return res, nil
	}
	selected := make(map[Kind]bool, len(opts.Kinds))
	for _, k := range opts.Kinds {
		selected[k] = true
	}

	targets, gaps := collectTargets(inv, selected)
	res.Gaps = gaps

	for _, k := range []Kind{APIServerVulnerabilities, KubeletVulnerabilities} {
		if !selected[k] {
			continue
		}
		switch {
		case opts.Index == nil:
			res.Gaps = append(res.Gaps, Gap{Kind: k, Selector: ClusterSelector, Reason: "Kubernetes CVE applicability index not available"})
		case opts.Index.Stale(opts.Now, opts.IndexMaxAge, opts.DBBuilt):
			res.Gaps = append(res.Gaps, Gap{Kind: k, Selector: ClusterSelector, Reason: fmt.Sprintf("Kubernetes CVE applicability index from %s is stale", opts.Index.Updated.Format(time.DateOnly))})
		}
	}

	if opts.Index == nil {
		// Kubernetes CVEs cannot be attributed, so there is nothing to match.
		targets = slices.DeleteFunc(targets, func(t target) bool { return isKubernetes(t.kind) })
	}

	if len(targets) > 0 {
		vulns, err := lookup(targets, m)
		if err != nil {
			return Result{}, err
		}
		for _, t := range targets {
			found := vulns[t.pkgID]
			if isKubernetes(t.kind) {
				var unattributed []string
				found, unattributed = applicable(found, opts.Index, t)
				if len(unattributed) > 0 {
					res.Gaps = append(res.Gaps, Gap{Kind: t.kind, Selector: t.selector, Reason: fmt.Sprintf("cannot attribute %s to %s %s", strings.Join(unattributed, ", "), t.version.Component, t.version.Version)})
				}
			}
			res.Resources = append(res.Resources, newResource(t, found, opts))
		}
	}

	slices.SortStableFunc(res.Gaps, func(a, b Gap) int {
		return cmp.Or(cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Selector, b.Selector))
	})
	return res, nil
}

func isKubernetes(k Kind) bool {
	return k == APIServerVulnerabilities || k == KubeletVulnerabilities
}

func collectTargets(inv clustercomponents.Inventory, selected map[Kind]bool) ([]target, []Gap) {
	var targets []target
	var gaps []Gap

	for _, g := range inv.Gaps {
		k, ok := kindOf(g.Component)
		if !ok || !selected[k] {
			continue
		}
		selector := g.Node
		if selector == "" {
			selector = ClusterSelector
		}
		gaps = append(gaps, Gap{Kind: k, Selector: selector, Reason: g.Reason})
	}

	if selected[APIServerVulnerabilities] && inv.APIServer != nil {
		// The control plane only runs on Linux.
		targets = append(targets, newTarget(APIServerVulnerabilities, string(clustercomponents.APIServer), "linux", ClusterSelector, *inv.APIServer))
	}
	for _, n := range inv.Nodes {
		if selected[KubeletVulnerabilities] && n.Kubelet != nil {
			targets = append(targets, newTarget(KubeletVulnerabilities, n.Name, n.OperatingSystem, n.Name, *n.Kubelet))
		}
		if selected[ContainerRuntimeVulnerabilities] && n.Runtime != nil {
			targets = append(targets, newTarget(ContainerRuntimeVulnerabilities, n.Name, n.OperatingSystem, n.Name, *n.Runtime))
		}
	}
	return targets, gaps
}

func kindOf(c clustercomponents.Component) (Kind, bool) {
	switch c {
	case clustercomponents.APIServer:
		return APIServerVulnerabilities, true
	case clustercomponents.Kubelet:
		return KubeletVulnerabilities, true
	case clustercomponents.Containerd, clustercomponents.CRIO, clustercomponents.ContainerRuntime:
		return ContainerRuntimeVulnerabilities, true
	}
	return "", false
}

func newTarget(k Kind, name, os, selector string, v clustercomponents.ComponentVersion) target {
	return target{kind: k, name: name, os: os, selector: selector, version: v, pkgID: pkg.ID(modulePath(v) + "@" + v.Version)}
}

func modulePath(v clustercomponents.ComponentVersion) string {
	switch v.Component {
	case clustercomponents.Containerd:
		if major, _, _ := strings.Cut(v.Version, "."); major != "0" && major != "1" {
			return containerdModule + "/v" + major
		}
		return containerdModule
	case clustercomponents.CRIO:
		return criOModule
	default:
		return kubernetesModule
	}
}

// lookup matches each distinct module version once, in a single matcher call.
func lookup(targets []target, m Matcher) (map[pkg.ID][]Vulnerability, error) {
	seen := make(map[pkg.ID]bool)
	var packages []pkg.Package
	for _, t := range targets {
		if seen[t.pkgID] {
			continue
		}
		seen[t.pkgID] = true
		name := modulePath(t.version)
		packages = append(packages, pkg.Package{
			ID:       t.pkgID,
			Name:     name,
			Version:  "v" + t.version.Version,
			Type:     syftPkg.GoModulePkg,
			Language: syftPkg.Go,
			PURL:     "pkg:golang/" + name + "@v" + t.version.Version,
		})
	}

	matches, _, err := m.MatchPackages(packages, pkg.Context{}, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("match cluster components: %w", err)
	}

	byPackage := make(map[pkg.ID]map[string]Vulnerability)
	for _, mt := range matches.Sorted() {
		v := toVulnerability(mt)
		found := byPackage[mt.Package.ID]
		if found == nil {
			found = make(map[string]Vulnerability)
			byPackage[mt.Package.ID] = found
		}
		if prev, ok := found[v.ID]; ok {
			v = merge(prev, v)
		}
		found[v.ID] = v
	}

	out := make(map[pkg.ID][]Vulnerability, len(byPackage))
	for id, found := range byPackage {
		vulns := make([]Vulnerability, 0, len(found))
		for _, v := range found {
			vulns = append(vulns, v)
		}
		slices.SortFunc(vulns, compareRisk)
		out[id] = vulns
	}
	return out, nil
}

// toVulnerability keys a match by its CVE when it has one, since advisories
// such as GHSAs are aliases and the applicability index is keyed by CVE.
func toVulnerability(m match.Match) Vulnerability {
	ids := []string{m.Vulnerability.ID}
	for _, r := range m.Vulnerability.RelatedVulnerabilities {
		if !slices.Contains(ids, r.ID) {
			ids = append(ids, r.ID)
		}
	}
	primary := slices.IndexFunc(ids, isCVE)
	if primary < 0 {
		primary = 0
	}

	v := Vulnerability{
		ID:       ids[primary],
		Aliases:  slices.Delete(slices.Clone(ids), primary, primary+1),
		FixState: m.Vulnerability.Fix.State.String(),
		FixedIn:  slices.Clone(m.Vulnerability.Fix.Versions),
		Severity: severityName(vulnerability.UnknownSeverity),
	}
	if md := m.Vulnerability.Metadata; md != nil {
		if md.Severity != "" {
			v.Severity = severityName(vulnerability.ParseSeverity(md.Severity))
		}
		v.KnownExploited = len(md.KnownExploited) > 0
		for _, e := range md.EPSS {
			if v.EPSS == nil || e.EPSS > *v.EPSS {
				score := e.EPSS
				v.EPSS = &score
			}
		}
	}
	if len(v.Aliases) == 0 {
		v.Aliases = nil
	}
	return v
}

// merge combines two records of the same CVE from different advisories,
// keeping the more severe and more exploited view of it.
func merge(a, b Vulnerability) Vulnerability {
	if vulnerability.ParseSeverity(b.Severity) > vulnerability.ParseSeverity(a.Severity) {
		a.Severity = b.Severity
	}
	a.KnownExploited = a.KnownExploited || b.KnownExploited
	if b.EPSS != nil && (a.EPSS == nil || *b.EPSS > *a.EPSS) {
		a.EPSS = b.EPSS
	}
	for _, alias := range b.Aliases {
		if !slices.Contains(a.Aliases, alias) {
			a.Aliases = append(a.Aliases, alias)
		}
	}
	for _, f := range b.FixedIn {
		if !slices.Contains(a.FixedIn, f) {
			a.FixedIn = append(a.FixedIn, f)
		}
	}
	if b.FixState == vulnerability.FixStateFixed.String() {
		a.FixState = b.FixState
	}
	slices.Sort(a.Aliases)
	slices.Sort(a.FixedIn)
	return a
}

// severityName spells severities the way image scan results do, e.g. "High".
func severityName(s vulnerability.Severity) string {
	name := s.String()
	return strings.ToUpper(name[:1]) + name[1:]
}

func isCVE(id string) bool {
	return strings.HasPrefix(strings.ToUpper(id), "CVE-")
}

// compareRisk orders known-exploited CVEs first, then by severity, then by
// EPSS score, so the evidence leads with what to patch first.
func compareRisk(a, b Vulnerability) int {
	if a.KnownExploited != b.KnownExploited {
		if a.KnownExploited {
			return -1
		}
		return 1
	}
	if c := cmp.Compare(vulnerability.ParseSeverity(b.Severity), vulnerability.ParseSeverity(a.Severity)); c != 0 {
		return c
	}
	if c := cmp.Compare(epssKey(b.EPSS), epssKey(a.EPSS)); c != 0 {
		return c
	}
	return cmp.Compare(a.ID, b.ID)
}

func epssKey(e *float64) float64 {
	if e == nil {
		return -1
	}
	return *e
}

// applicable keeps the Kubernetes CVEs the index attributes to the target's
// component and returns the ones it cannot attribute either way.
func applicable(vulns []Vulnerability, ix *k8scveindex.Index, t target) (kept []Vulnerability, unattributed []string) {
	for _, v := range vulns {
		switch ix.Lookup(v.ID, string(t.version.Component), t.version.Version, t.os) {
		case k8scveindex.Applicable:
			kept = append(kept, v)
		case k8scveindex.Unattributed:
			unattributed = append(unattributed, v.ID)
		}
	}
	return kept, unattributed
}

func newResource(t target, vulns []Vulnerability, opts Options) workloadinterface.IMetadata {
	if vulns == nil {
		vulns = []Vulnerability{}
	}
	data := map[string]any{
		"component":       string(t.version.Component),
		"version":         t.version.Version,
		"rawVersion":      t.version.RawVersion,
		"assessment":      string(t.version.Assessment),
		"vulnerabilities": vulns,
	}
	if t.os != "" && t.kind != APIServerVulnerabilities {
		data["operatingSystem"] = t.os
	}
	if isKubernetes(t.kind) && opts.Index != nil {
		data["applicabilityIndexDate"] = opts.Index.Updated.UTC().Format(time.DateOnly)
	}
	if !opts.DBBuilt.IsZero() {
		data["dbBuilt"] = opts.DBBuilt.UTC().Format(time.DateOnly)
	}
	return workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": APIVersion,
		"kind":       string(t.kind),
		"metadata":   map[string]any{"name": t.name},
		"data":       toJSONValue(data),
	})
}

// toJSONValue converts v to the plain maps and slices that rule input and
// the anonymizer expect from unstructured objects.
func toJSONValue(v map[string]any) map[string]any {
	raw, err := json.Marshal(v)
	if err != nil {
		return v
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return v
	}
	return out
}
