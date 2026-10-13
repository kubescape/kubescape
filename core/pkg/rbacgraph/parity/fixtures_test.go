package parity

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/semver"
)

const fixturesDir = "testdata"

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func loadFixtures(t *testing.T) []Fixture {
	t.Helper()
	fixtures, err := LoadFixtures(fixturesDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(fixtures) == 0 {
		t.Fatalf("no fixtures found in %s", fixturesDir)
	}
	return fixtures
}

// TestKubescapeMatchesRecordedKubernetesAnswers puts every fixture question
// to rbacgraph and requires the answer the fixture records for Kubernetes.
// It needs no cluster. What makes the recorded answers true is the reference
// run in reference_test.go, which checks each of them against a real
// kube-apiserver.
func TestKubescapeMatchesRecordedKubernetesAnswers(t *testing.T) {
	for _, f := range loadFixtures(t) {
		t.Run(f.Name, func(t *testing.T) {
			kubescape, err := NewKubescape(f)
			if err != nil {
				t.Fatal(err)
			}
			for _, q := range f.Questions {
				if err := Compare(f.Name, q, q.Kubernetes, kubescape.Answer(q)); err != nil {
					t.Error(err)
				}
			}
		})
	}
}

// referenceVersions parses reference.env, the one place the reference
// Kubernetes version is written down.
func referenceVersions(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile("reference.env")
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("reference.env: %q is not KEY=value", line)
		}
		values[key] = value
	}
	return values
}

// TestReferenceTracksGoMod ties the pinned reference to the Kubernetes
// libraries this repository builds against. rbacgraph is compiled with the
// k8s.io/api types of one Kubernetes minor, so that is the minor whose
// semantics it has to match; when the dependency moves to the next one, this
// fails until the reference moves with it and the fixtures are verified
// again.
func TestReferenceTracksGoMod(t *testing.T) {
	versions := referenceVersions(t)

	reference := versions["KUBE_APISERVER_VERSION"]
	if !regexp.MustCompile(`^v1\.\d+\.\d+$`).MatchString(reference) {
		t.Fatalf("reference.env: KUBE_APISERVER_VERSION = %q, want an exact release such as v1.37.1", reference)
	}
	if !regexp.MustCompile(`^v\d+\.\d+\.\d+$`).MatchString(versions["ETCD_VERSION"]) {
		t.Errorf("reference.env: ETCD_VERSION = %q, want an exact release such as v3.7.0", versions["ETCD_VERSION"])
	}
	sha256 := regexp.MustCompile(`^[0-9a-f]{64}$`)
	for _, key := range []string{"KUBE_APISERVER_SHA256_LINUX_AMD64", "KUBE_APISERVER_SHA256_LINUX_ARM64", "ETCD_SHA256_LINUX_AMD64", "ETCD_SHA256_LINUX_ARM64"} {
		if !sha256.MatchString(versions[key]) {
			t.Errorf("reference.env: %s = %q, want a SHA-256 checksum", key, versions[key])
		}
	}

	const goModPath = "../../../../go.mod"
	raw, err := os.ReadFile(goModPath)
	if err != nil {
		t.Fatal(err)
	}
	goMod, err := modfile.Parse(goModPath, raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	var api string
	for _, r := range goMod.Require {
		if r.Mod.Path == "k8s.io/api" {
			api = r.Mod.Version
		}
	}
	if api == "" {
		t.Fatal("go.mod does not require k8s.io/api")
	}
	// k8s.io/api v0.X.Y is published from Kubernetes v1.X.Y.
	want := "v1" + strings.TrimPrefix(semver.MajorMinor(api), "v0")
	if got := semver.MajorMinor(reference); got != want {
		t.Errorf("reference.env pins Kubernetes %s (%s) but go.mod requires k8s.io/api %s (Kubernetes %s): move the reference in reference.env and run the reference tests (see README.md)",
			reference, got, api, want)
	}
}
