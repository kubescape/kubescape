package vulnexposure

import (
	"testing"

	"github.com/kubescape/kubescape/v4/core/pkg/networkpolicy"
	storagev1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func vuln(id, severity string, fixed bool) storagev1beta1.Vulnerability {
	v := storagev1beta1.Vulnerability{
		VulnerabilityMetadata: storagev1beta1.VulnerabilityMetadata{ID: id, Severity: severity},
	}
	if fixed {
		v.Fix = storagev1beta1.Fix{Versions: []string{"1.2.4"}, State: "fixed"}
	}
	return v
}

func TestParseSeverity(t *testing.T) {
	cases := map[string]Severity{
		"Critical":   SeverityCritical,
		"CRITICAL":   SeverityCritical,
		"high":       SeverityHigh,
		"Medium":     SeverityMedium,
		"low":        SeverityLow,
		"Negligible": SeverityNegligible,
		"":           SeverityUnknown,
		"garbage":    SeverityUnknown,
	}
	for input, want := range cases {
		if got := ParseSeverity(input); got != want {
			t.Errorf("ParseSeverity(%q) = %v, want %v", input, got, want)
		}
	}
}

func TestSeverityOrdering(t *testing.T) {
	ordered := []Severity{SeverityUnknown, SeverityNegligible, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
	for i := 1; i < len(ordered); i++ {
		if ordered[i] <= ordered[i-1] {
			t.Fatalf("severity levels must strictly increase: %v is not greater than %v", ordered[i], ordered[i-1])
		}
	}
}

func openIndex(t *testing.T) *networkpolicy.Index {
	t.Helper()
	idx, errs := networkpolicy.NewIndex(nil, nil)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	return idx
}

func TestCorrelate_SkipsWorkloadWithoutResolvedEndpoint(t *testing.T) {
	idx := openIndex(t)
	w := Workload{Namespace: "prod", Kind: "Deployment", Name: "web"}

	findings, skipped := Correlate(idx, nil, map[Workload][]storagev1beta1.Vulnerability{
		w: {vuln("CVE-1", "Critical", true)},
	}, SeverityLow)

	if len(findings) != 0 {
		t.Errorf("expected no findings for an unresolved workload, got %d", len(findings))
	}
	if len(skipped) != 1 || skipped[0] != w {
		t.Errorf("expected %v in skipped, got %v", w, skipped)
	}
}

func TestCorrelate_FiltersBelowMinSeverity(t *testing.T) {
	idx := openIndex(t)
	w := Workload{Namespace: "prod", Kind: "Deployment", Name: "web"}
	endpoints := map[Workload]networkpolicy.Endpoint{
		w: {Namespace: "prod", Name: "web", Labels: map[string]string{"app": "web"}},
	}

	findings, _ := Correlate(idx, endpoints, map[Workload][]storagev1beta1.Vulnerability{
		w: {vuln("CVE-LOW", "Low", false), vuln("CVE-CRIT", "Critical", true)},
	}, SeverityHigh)

	if len(findings) != 1 || findings[0].Vulnerability.ID != "CVE-CRIT" {
		t.Errorf("expected only CVE-CRIT to survive the High threshold, got %+v", findings)
	}
}

func TestCorrelate_CarriesFixAvailable(t *testing.T) {
	idx := openIndex(t)
	w := Workload{Namespace: "prod", Kind: "Deployment", Name: "web"}
	endpoints := map[Workload]networkpolicy.Endpoint{
		w: {Namespace: "prod", Name: "web", Labels: map[string]string{"app": "web"}},
	}

	findings, _ := Correlate(idx, endpoints, map[Workload][]storagev1beta1.Vulnerability{
		w: {vuln("CVE-FIXED", "Critical", true), vuln("CVE-UNFIXED", "Critical", false)},
	}, SeverityLow)

	byID := map[string]bool{}
	for _, f := range findings {
		byID[f.Vulnerability.ID] = f.FixAvailable
	}
	if !byID["CVE-FIXED"] {
		t.Error("CVE-FIXED must have FixAvailable = true")
	}
	if byID["CVE-UNFIXED"] {
		t.Error("CVE-UNFIXED must have FixAvailable = false")
	}
}

func TestCorrelate_ExposureIsAttachedFromTheIndex(t *testing.T) {
	// No NetworkPolicy at all selects this workload, so it must come back
	// ExposureOpen -- proves Correlate actually calls into the real
	// reachability model rather than a stub.
	idx := openIndex(t)
	w := Workload{Namespace: "prod", Kind: "Deployment", Name: "web"}
	endpoints := map[Workload]networkpolicy.Endpoint{
		w: {Namespace: "prod", Name: "web", Labels: map[string]string{"app": "web"}},
	}

	findings, _ := Correlate(idx, endpoints, map[Workload][]storagev1beta1.Vulnerability{
		w: {vuln("CVE-1", "Critical", true)},
	}, SeverityLow)

	if len(findings) != 1 || findings[0].Exposure.Level != networkpolicy.ExposureOpen {
		t.Errorf("expected ExposureOpen (no policy selects this workload), got %+v", findings)
	}
}

func TestCorrelate_SortsWidestExposureAndHighestSeverityFirst(t *testing.T) {
	restrictiveSel := metav1.LabelSelector{MatchLabels: map[string]string{"app": "restricted"}}
	restrictivePolicy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "restrict"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: restrictiveSel,
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}}}},
			}},
		},
	}
	idx, errs := networkpolicy.NewIndex([]*networkingv1.NetworkPolicy{restrictivePolicy}, nil)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}

	openWorkload := Workload{Namespace: "prod", Kind: "Deployment", Name: "open-app"}
	restrictedWorkload := Workload{Namespace: "prod", Kind: "Deployment", Name: "restricted-app"}
	endpoints := map[Workload]networkpolicy.Endpoint{
		openWorkload:       {Namespace: "prod", Name: "open-app", Labels: map[string]string{"app": "open"}},
		restrictedWorkload: {Namespace: "prod", Name: "restricted-app", Labels: map[string]string{"app": "restricted"}},
	}

	findings, _ := Correlate(idx, endpoints, map[Workload][]storagev1beta1.Vulnerability{
		openWorkload:       {vuln("CVE-OPEN", "Critical", true)},
		restrictedWorkload: {vuln("CVE-RESTRICTED", "Critical", true)},
	}, SeverityLow)

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	if findings[0].Vulnerability.ID != "CVE-OPEN" {
		t.Errorf("expected the ExposureOpen workload's finding first, got %+v", findings[0])
	}
}
