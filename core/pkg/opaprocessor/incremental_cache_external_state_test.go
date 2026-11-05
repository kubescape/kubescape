package opaprocessor

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testRegistry is an in-memory OCI registry on a loopback address, which the
// registry client reaches over plain HTTP. It counts requests and can be
// switched into an outage.
type testRegistry struct {
	requests atomic.Int64
	down     atomic.Bool
	repo     name.Repository
}

func newTestRegistry(t *testing.T) *testRegistry {
	t.Helper()
	r := &testRegistry{}
	handler := registry.New()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.requests.Add(1)
		if r.down.Load() {
			http.Error(w, "registry unavailable", http.StatusServiceUnavailable)
			return
		}
		handler.ServeHTTP(w, req)
	}))
	t.Cleanup(server.Close)
	repo, err := name.NewRepository(strings.TrimPrefix(server.URL, "http://") + "/app")
	require.NoError(t, err)
	r.repo = repo
	return r
}

// pushImage pushes a new random image under tag and returns its digest.
func (r *testRegistry) pushImage(t *testing.T, tag string) v1.Hash {
	t.Helper()
	image, err := random.Image(128, 1)
	require.NoError(t, err)
	require.NoError(t, remote.Write(r.repo.Tag(tag), image))
	digest, err := image.Digest()
	require.NoError(t, err)
	return digest
}

// signImage attaches a cosign-style signature to the image with digest, which
// is what cosign.has_signature looks for.
func (r *testRegistry) signImage(t *testing.T, digest v1.Hash) {
	t.Helper()
	layer := static.NewLayer([]byte(`{"critical":{}}`), types.MediaType("application/vnd.dev.cosign.simplesigning.v1+json"))
	signature, err := mutate.Append(empty.Image, mutate.Addendum{
		Layer:       layer,
		Annotations: map[string]string{"dev.cosignproject.cosign/signature": "MEUCIQ=="},
	})
	require.NoError(t, err)
	require.NoError(t, remote.Write(r.repo.Tag(strings.Replace(digest.String(), ":", "-", 1)+".sig"), signature))
}

// hasSignaturePodRule is the Pod body of regolibrary's has-image-signature
// (C-0237), matched on Pods only so the rule passes every other cache
// eligibility condition, as a custom single-kind control can.
const hasSignaturePodRule = `package armo_builtins
import rego.v1

deny contains msga if {
	pod := input[_]
	pod.kind == "Pod"
	container := pod.spec.containers[i]
	not cosign.has_signature(container.image)
	failedPath := sprintf("spec.containers[%v].image", [format_int(i, 10)])
	msga := {
		"alertMessage": sprintf("image: %v is not signed", [container.image]),
		"alertScore": 7,
		"fixPaths": [],
		"reviewPaths": [failedPath],
		"failedPaths": [failedPath],
		"packagename": "armo_builtins",
		"alertObject": {"k8sApiObjects": [pod]},
	}
}
`

// verifySignaturePodRule is the Pod body of regolibrary's
// verify-image-signature (C-0236) with the trusted key inlined.
const verifySignaturePodRule = `package armo_builtins
import rego.v1

deny contains msga if {
	pod := input[_]
	pod.kind == "Pod"
	container := pod.spec.containers[i]
	not cosign.verify(container.image, %q)
	failedPath := sprintf("spec.containers[%%v].image", [format_int(i, 10)])
	msga := {
		"alertMessage": sprintf("signature not verified for image: %%v", [container.image]),
		"alertScore": 7,
		"fixPaths": [],
		"reviewPaths": [failedPath],
		"failedPaths": [failedPath],
		"packagename": "armo_builtins",
		"alertObject": {"k8sApiObjects": [pod]},
	}
}
`

func imagePod(name, image string) map[string]any {
	return podObject("prod", name, map[string]any{
		"containers": []any{map[string]any{"name": "app", "image": image}},
	})
}

func TestSignatureRulesAreNotCacheable(t *testing.T) {
	key := testPublicKeyPEM(t)
	for name, source := range map[string]string{
		"has-image-signature (C-0237)":    hasSignaturePodRule,
		"verify-image-signature (C-0236)": fmt.Sprintf(verifySignaturePodRule, key),
	} {
		t.Run(name, func(t *testing.T) {
			assert.False(t, regoSourceIsHermetic(source))
			for _, kinds := range [][]string{{"Pod"}, {"Pod", "Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job", "CronJob"}} {
				control := regoControl("C-SIG", "signature", source, kinds...)
				assert.False(t, controlCacheEligible(&control), "kinds %v", kinds)
			}
		})
	}
}

// A registry outage makes cosign.has_signature return false, which a cached
// verdict would keep reporting after the registry recovers.
func TestIncrementalCacheDoesNotKeepARegistryOutage(t *testing.T) {
	reg := newTestRegistry(t)
	reg.signImage(t, reg.pushImage(t, "v1"))

	scenario := newCacheScenario(t, regoControl("C-SIG", "pod-has-signature", hasSignaturePodRule, "Pod"))
	id := scenario.put("/v1/pods", imagePod("web", reg.repo.Tag("v1").String()))

	reg.down.Store(true)
	full, incremental := scenario.step()
	require.Equal(t, "failed", full[id].Status, "an outage reads as an unsigned image")
	assert.Equal(t, full, incremental)

	reg.down.Store(false)
	full, incremental = scenario.step()
	require.Equal(t, "passed", full[id].Status)
	assert.Equal(t, full, incremental, "the outage must not outlive the registry recovering")
}

// Repointing a tag to an unsigned image changes the verdict without changing
// the workload.
func TestIncrementalCacheFollowsATagRepointedToAnUnsignedImage(t *testing.T) {
	reg := newTestRegistry(t)
	reg.signImage(t, reg.pushImage(t, "v1"))

	scenario := newCacheScenario(t, regoControl("C-SIG", "pod-has-signature", hasSignaturePodRule, "Pod"))
	id := scenario.put("/v1/pods", imagePod("web", reg.repo.Tag("v1").String()))

	full, incremental := scenario.step()
	require.Equal(t, "passed", full[id].Status)
	assert.Equal(t, full, incremental)

	reg.pushImage(t, "v1")
	full, incremental = scenario.step()
	require.Equal(t, "failed", full[id].Status)
	assert.Equal(t, full, incremental, "a signed verdict must not survive the tag moving to an unsigned image")
}

// cosign.verify consults the registry on every scan: an incremental scan of an
// unchanged workload still asks the registry.
func TestIncrementalCacheVerifiesSignaturesOnEveryScan(t *testing.T) {
	reg := newTestRegistry(t)
	reg.pushImage(t, "v1")

	source := fmt.Sprintf(verifySignaturePodRule, testPublicKeyPEM(t))
	scenario := newCacheScenario(t, regoControl("C-VERIFY", "pod-verify-signature", source, "Pod"))
	id := scenario.put("/v1/pods", imagePod("web", reg.repo.Tag("v1").String()))

	for _, step := range []string{"cold", "warm"} {
		full := scenario.evaluate(nil)
		store := scenario.loadStore()
		before := reg.requests.Load()
		incremental := scenario.evaluate(store)
		require.NoError(t, store.Flush())

		assert.Equal(t, "failed", full[id].Status, step)
		assert.Equal(t, full, incremental, step)
		assert.Positive(t, reg.requests.Load()-before, "%s: the incremental scan must verify against the registry", step)
	}
}

func testPublicKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

const schemaRule = `package armo_builtins
import rego.v1

deny contains msga if {
	pod := input[_]
	[ok, _] := json.match_schema(pod.spec, {"$ref": %q})
	not ok
	msga := {
		"alertMessage": "spec does not match the schema",
		"alertScore": 1,
		"failedPaths": [],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"k8sApiObjects": [pod]},
	}
}
`

const (
	strictSchema     = `{"type":"object","required":["securityContext"]}`
	permissiveSchema = `{"type":"object"}`
)

// json.match_schema resolves a remote $ref at evaluation time.
func TestIncrementalCacheFollowsARemoteJSONSchema(t *testing.T) {
	var schema atomic.Value
	schema.Store(strictSchema)
	var fetches atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		_, _ = w.Write([]byte(schema.Load().(string)))
	}))
	t.Cleanup(server.Close)

	scenario := newCacheScenario(t, regoControl("C-SCHEMA", "remote-schema", fmt.Sprintf(schemaRule, server.URL+"/schema.json"), "Pod"))
	id := scenario.put("/v1/pods", podObject("prod", "web", map[string]any{"containers": []any{}}))

	full, incremental := scenario.step()
	require.Equal(t, "failed", full[id].Status)
	require.Positive(t, fetches.Load(), "the schema is fetched during evaluation")
	assert.Equal(t, full, incremental)

	schema.Store(permissiveSchema)
	full, incremental = scenario.step()
	require.Equal(t, "passed", full[id].Status, "the remote schema changed")
	assert.Equal(t, full, incremental, "a verdict must not outlive the schema it was checked against")
}

// json.match_schema also resolves a file $ref from the local filesystem.
func TestIncrementalCacheFollowsAFileJSONSchema(t *testing.T) {
	schemaPath := filepath.Join(t.TempDir(), "schema.json")
	require.NoError(t, os.WriteFile(schemaPath, []byte(strictSchema), 0o600))
	fileURL := "file://" + filepath.ToSlash(schemaPath)
	if !strings.HasPrefix(filepath.ToSlash(schemaPath), "/") {
		fileURL = "file:///" + filepath.ToSlash(schemaPath)
	}

	scenario := newCacheScenario(t, regoControl("C-SCHEMA", "file-schema", fmt.Sprintf(schemaRule, fileURL), "Pod"))
	id := scenario.put("/v1/pods", podObject("prod", "web", map[string]any{"containers": []any{}}))

	full, incremental := scenario.step()
	require.Equal(t, "failed", full[id].Status)
	assert.Equal(t, full, incremental)

	require.NoError(t, os.WriteFile(schemaPath, []byte(permissiveSchema), 0o600))
	full, incremental = scenario.step()
	require.Equal(t, "passed", full[id].Status, "the schema file changed")
	assert.Equal(t, full, incremental, "a verdict must not outlive the schema file it was checked against")
}
