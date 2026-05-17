//go:build integration_patch
// +build integration_patch

// Integration test for the patch command's default (no-push) path.
//
// This is the proof that with the documented `sudo buildkitd` flow the patched image really does land
// in the user's docker image store. It is gated behind the `integration_patch`
// build tag so it is never picked up by `go test ./...` in normal CI.
//
// To run it locally:
//
//	# 1. Start a registry and seed a source image you have access to.
//	docker run -d --name kubescape-it-registry -p 5000:5000 registry:2
//	docker pull nginx:1.23
//	docker tag nginx:1.23 localhost:5000/test/nginx:1.23
//	docker push localhost:5000/test/nginx:1.23
//
//	# 2. Start standalone buildkitd (or reuse an existing one) and make the
//	#    socket reachable to your user.
//	sudo /usr/local/bin/buildkitd &
//	sudo chmod 755 /run/buildkit && sudo chmod 666 /run/buildkit/buildkitd.sock
//
//	# 3. Run the test.
//	go test -tags integration_patch ./core/core/... -run TestPatchDefault_NoPush_LoadsLocally -v
//
// Override defaults via env: PATCH_IT_SOURCE_IMAGE, PATCH_IT_BUILDKIT_ADDR,
// PATCH_IT_REGISTRY.

package core

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	defaultSourceImage   = "localhost:5000/test/nginx:1.23"
	defaultBuildkitAddr  = "unix:///run/buildkit/buildkitd.sock"
	defaultRegistry      = "localhost:5000"
	defaultRepoUnderTest = "test/nginx"
)

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// TestPatchDefault_NoPush_LoadsLocally drives the built kubescape binary
// end-to-end against a real buildkitd + dockerd + registry and asserts the
// post-condition that originally regressed:
//   - the patched tag is resolvable via dockerd (`docker image inspect`),
//   - the source registry was NOT pushed to.
//
// This is the failure mode matthyx flagged: ExporterImage in the no-push
// branch left the patched image in buildkit's worker store, invisible to
// dockerd on the standalone `sudo buildkitd` flow.
func TestPatchDefault_NoPush_LoadsLocally(t *testing.T) {
	src := env("PATCH_IT_SOURCE_IMAGE", defaultSourceImage)
	buildkitAddr := env("PATCH_IT_BUILDKIT_ADDR", defaultBuildkitAddr)
	registry := env("PATCH_IT_REGISTRY", defaultRegistry)

	requireToolsOrSkip(t)
	requireBuildkitSocketOrSkip(t, buildkitAddr)
	requireRegistryOrSkip(t, registry)
	requireSourceImageOrSkip(t, src)

	bin := buildKubescape(t)

	// Use a unique source tag so we can assert "this run" did not push it.
	uniqueTag := fmt.Sprintf("itload-%d", time.Now().UnixNano())
	uniqueRef := fmt.Sprintf("%s/%s:%s", registry, defaultRepoUnderTest, uniqueTag)
	patchedRef := fmt.Sprintf("%s/%s:%s-patched", registry, defaultRepoUnderTest, uniqueTag)

	runOrFatal(t, "docker", "tag", src, uniqueRef)
	runOrFatal(t, "docker", "push", uniqueRef)
	t.Cleanup(func() {
		_ = exec.Command("docker", "rmi", uniqueRef).Run()
		_ = exec.Command("docker", "rmi", patchedRef).Run()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin,
		"patch",
		"-i", uniqueRef,
		"-a", buildkitAddr,
	)
	cmd.Env = append(os.Environ(), "KUBESCAPE_SKIP_UPDATE_CHECK=true")
	out, err := cmd.CombinedOutput()
	t.Logf("kubescape patch output (last 60 lines):\n%s", tailLines(string(out), 60))
	if err != nil {
		t.Fatalf("kubescape patch failed: %v", err)
	}

	// Post-condition 1: patched image is in dockerd's store.
	inspectOut, inspectErr := exec.Command("docker", "image", "inspect",
		"--format", "{{.Id}} layers={{len .RootFS.Layers}}", patchedRef).CombinedOutput()
	if inspectErr != nil {
		t.Fatalf("docker image inspect %s failed: %v\noutput: %s\n\n"+
			"This is the regression matthyx flagged: the no-push path must put the "+
			"patched image into dockerd's image store. ExporterImage does not "+
			"guarantee this on the standalone buildkitd flow.",
			patchedRef, inspectErr, inspectOut)
	}
	t.Logf("patched image present in dockerd: %s", strings.TrimSpace(string(inspectOut)))

	// Post-condition 2: source registry was NOT pushed to.
	tags := registryTags(t, registry, defaultRepoUnderTest)
	for _, tg := range tags {
		if tg == uniqueTag+"-patched" {
			t.Fatalf("default path must not push, but registry now has tag %q (full list: %v)",
				tg, tags)
		}
	}
}

func requireToolsOrSkip(t *testing.T) {
	t.Helper()
	for _, bin := range []string{"docker", "go"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("integration test requires %q on PATH: %v", bin, err)
		}
	}
}

func requireBuildkitSocketOrSkip(t *testing.T, addr string) {
	t.Helper()
	if !strings.HasPrefix(addr, "unix://") {
		// TCP — assume reachable; the build call will surface a clearer error if not.
		return
	}
	socket := strings.TrimPrefix(addr, "unix://")
	if _, err := os.Stat(socket); err != nil {
		t.Skipf("buildkitd socket %s not reachable: %v", socket, err)
	}
	// Confirm we can actually connect — stat alone doesn't prove the socket
	// is accessible to this user (parent dir + socket mode both matter).
	conn, err := net.DialTimeout("unix", socket, 2*time.Second)
	if err != nil {
		t.Skipf("buildkitd socket %s exists but this user cannot connect: %v\n"+
			"Try: sudo chmod 755 %s && sudo chmod 666 %s",
			socket, err, filepath.Dir(socket), socket)
	}
	_ = conn.Close()
}

func requireRegistryOrSkip(t *testing.T, registry string) {
	t.Helper()
	url := fmt.Sprintf("http://%s/v2/", registry)
	c := &http.Client{Timeout: 2 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		t.Skipf("local registry %s not reachable: %v", registry, err)
	}
	defer resp.Body.Close()
}

func requireSourceImageOrSkip(t *testing.T, src string) {
	t.Helper()
	if err := exec.Command("docker", "image", "inspect", src).Run(); err != nil {
		t.Skipf("source image %s not present locally — pull/tag/push it first", src)
	}
}

func registryTags(t *testing.T, registry, repo string) []string {
	t.Helper()
	url := fmt.Sprintf("http://%s/v2/%s/tags/list", registry, repo)
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		t.Fatalf("registry tag list GET failed: %v", err)
	}
	defer resp.Body.Close()
	var body struct {
		Tags []string `json:"tags"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("registry tag list decode failed: %v", err)
	}
	return body.Tags
}

// buildKubescape builds the kubescape binary from the current repo into a
// temp dir. Building inside the test (rather than relying on an external
// build step) keeps the test honest: it always exercises the code at HEAD.
func buildKubescape(t *testing.T) string {
	t.Helper()
	repoRoot, err := findRepoRoot()
	if err != nil {
		t.Fatalf("locate repo root: %v", err)
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "kubescape")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build kubescape failed: %v\n%s", err, out)
	}
	return bin
}

func findRepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found above cwd")
		}
		dir = parent
	}
}

func runOrFatal(t *testing.T, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s failed: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}

func tailLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) <= n {
		return s
	}
	return strings.Join(lines[len(lines)-n:], "\n")
}
