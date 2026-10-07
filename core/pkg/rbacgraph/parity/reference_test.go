//go:build rbacparity

package parity

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"golang.org/x/mod/semver"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// allowOtherPatchEnv lets the reference tests run against another patch
// release of the pinned Kubernetes minor. Kubernetes publishes kube-apiserver
// for Linux only, so on other systems the nearest thing available is the
// envtest build of that minor. CI never sets it.
const allowOtherPatchEnv = "RBAC_PARITY_ALLOW_OTHER_PATCH"

// reference is one kube-apiserver and etcd, started by envtest from the
// binaries in KUBEBUILDER_ASSETS. There is no kubelet and no controller
// manager: authorization, and the escalation checks the RBAC registry makes
// on writes, both happen inside the API server.
type reference struct {
	config  *rest.Config
	admin   kubernetes.Interface
	version string
}

// startReference never skips. A reference run that could not start a server
// has verified nothing, and reporting that as a pass is the failure this
// package exists to prevent.
func startReference(t *testing.T) *reference {
	t.Helper()
	env := &envtest.Environment{}
	config, err := env.Start()
	if err != nil {
		t.Fatalf("starting kube-apiserver and etcd from KUBEBUILDER_ASSETS=%q: %v\nrun fetch-reference.sh to download the pinned binaries (see README.md)", os.Getenv("KUBEBUILDER_ASSETS"), err)
	}
	t.Cleanup(func() {
		if err := env.Stop(); err != nil {
			t.Errorf("stopping the reference control plane: %v", err)
		}
	})

	admin, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	version, err := admin.Discovery().ServerVersion()
	if err != nil {
		t.Fatalf("reading the reference server version: %v", err)
	}
	return &reference{config: config, admin: admin, version: version.GitVersion}
}

// requirePinnedVersion fails unless the server is the release reference.env
// pins. The check is on what the server reports, not on what was asked for.
func requirePinnedVersion(t *testing.T, got string) {
	t.Helper()
	want := referenceVersions(t)["KUBE_APISERVER_VERSION"]
	if got == want {
		return
	}
	if os.Getenv(allowOtherPatchEnv) != "" && semver.MajorMinor(got) == semver.MajorMinor(want) {
		t.Logf("WARNING: the reference server is %s, not the pinned %s; accepted because %s is set. This run does not verify the fixtures for %s.", got, want, allowOtherPatchEnv, want)
		return
	}
	t.Fatalf("the reference server is Kubernetes %s but reference.env pins %s", got, want)
}

// TestRecordedAnswersMatchKubernetes is the authoritative half of the parity
// tests. For every fixture it starts a fresh control plane, creates the
// fixture's objects, and makes each question's request as the ServiceAccount
// itself, with a token issued for it. The answer the fixture records for
// Kubernetes must be the one the server gives, and rbacgraph is then held to
// that live answer directly.
//
// A fixture gets a control plane of its own so that nothing one fixture binds
// (a group such as system:authenticated, say) can change the answer to a
// question in another.
func TestRecordedAnswersMatchKubernetes(t *testing.T) {
	fixtures := loadFixtures(t)

	// due counts the questions of every fixture that ran, so that a go test
	// -run filter narrows the check instead of tripping it.
	due, answered := 0, 0
	var version string
	for _, f := range fixtures {
		t.Run(f.Name, func(t *testing.T) {
			due += len(f.Questions)
			ref := startReference(t)
			requirePinnedVersion(t, ref.version)
			version = ref.version
			ref.create(t, f)

			kubescape, err := NewKubescape(f)
			if err != nil {
				t.Fatal(err)
			}
			for _, q := range f.Questions {
				live := ref.answer(t, q)
				answered++
				if err := CheckRecorded(f.Name, q, live, ref.version); err != nil {
					t.Error(err)
				}
				if err := Compare(f.Name, q, live, kubescape.Answer(q)); err != nil {
					t.Error(err)
				}
			}
		})
	}

	if answered != due {
		t.Errorf("the reference answered %d of %d questions: every question has to be verified", answered, due)
	}
	if !t.Failed() {
		t.Logf("verified %d questions against kube-apiserver %s", answered, version)
	}
}

// create installs the fixture's objects, Namespaces first.
func (r *reference) create(t *testing.T, f Fixture) {
	t.Helper()
	ctx := context.Background()
	opts := metav1.CreateOptions{}

	decode := func(obj map[string]any, into any) {
		t.Helper()
		raw, err := json.Marshal(obj)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, into); err != nil {
			t.Fatal(err)
		}
	}

	for _, namespacesPass := range []bool{true, false} {
		for _, obj := range f.Objects {
			kind, _ := obj["kind"].(string)
			if (kind == "Namespace") != namespacesPass {
				continue
			}
			var err error
			switch kind {
			case "Namespace":
				var o corev1.Namespace
				decode(obj, &o)
				_, err = r.admin.CoreV1().Namespaces().Create(ctx, &o, opts)
			case "ServiceAccount":
				var o corev1.ServiceAccount
				decode(obj, &o)
				_, err = r.admin.CoreV1().ServiceAccounts(o.Namespace).Create(ctx, &o, opts)
			case "Role":
				var o rbacv1.Role
				decode(obj, &o)
				_, err = r.admin.RbacV1().Roles(o.Namespace).Create(ctx, &o, opts)
			case "ClusterRole":
				var o rbacv1.ClusterRole
				decode(obj, &o)
				_, err = r.admin.RbacV1().ClusterRoles().Create(ctx, &o, opts)
			case "RoleBinding":
				var o rbacv1.RoleBinding
				decode(obj, &o)
				_, err = r.admin.RbacV1().RoleBindings(o.Namespace).Create(ctx, &o, opts)
			case "ClusterRoleBinding":
				var o rbacv1.ClusterRoleBinding
				decode(obj, &o)
				_, err = r.admin.RbacV1().ClusterRoleBindings().Create(ctx, &o, opts)
			default:
				t.Fatalf("fixture %q: cannot create an object of kind %q", f.Name, kind)
			}
			if err != nil {
				t.Fatalf("fixture %q: creating %s: %v", f.Name, kind, err)
			}
		}
	}
}

// as returns a client that authenticates as the ServiceAccount with a token
// from the TokenRequest API, so the request is authorized for exactly the
// identity the API server derives from a real ServiceAccount token.
func (r *reference) as(t *testing.T, sa ServiceAccountRef) kubernetes.Interface {
	t.Helper()
	token, err := r.admin.CoreV1().ServiceAccounts(sa.Namespace).CreateToken(context.Background(), sa.Name, &authenticationv1.TokenRequest{}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("issuing a token for %s: %v", sa, err)
	}
	config := rest.AnonymousClientConfig(r.config)
	config.BearerToken = token.Status.Token
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// everything is a rule no fixture subject holds, so writing it into a Role
// is an escalation whatever the Role granted before.
var everything = []rbacv1.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}}

// answer makes the request the question describes. Every write is a
// server-side dry run: it goes through authorization and the registry's
// escalation checks like any other request and changes nothing, so one
// question cannot affect the next.
func (r *reference) answer(t *testing.T, q Question) Answer {
	t.Helper()
	ctx := context.Background()
	client := r.as(t, q.ServiceAccount)
	dryRun := []string{metav1.DryRunAll}

	var err error
	switch {
	case q.MintToken != nil:
		// TokenRequest stores nothing, so it needs no dry run.
		_, err = client.CoreV1().ServiceAccounts(q.MintToken.Namespace).CreateToken(ctx, q.MintToken.Name, &authenticationv1.TokenRequest{}, metav1.CreateOptions{})

	case q.RewriteRole != nil:
		roles := client.RbacV1().Roles(q.RewriteRole.Namespace)
		if q.RewriteRole.Verb == "patch" {
			var patch []byte
			patch, err = json.Marshal(map[string]any{"rules": everything})
			if err != nil {
				t.Fatal(err)
			}
			_, err = roles.Patch(ctx, q.RewriteRole.Name, types.MergePatchType, patch, metav1.PatchOptions{DryRun: dryRun})
			break
		}
		// The current object is read as the administrator: the question is
		// whether the subject may write it, not whether it may read it.
		role, getErr := r.admin.RbacV1().Roles(q.RewriteRole.Namespace).Get(ctx, q.RewriteRole.Name, metav1.GetOptions{})
		if getErr != nil {
			t.Fatalf("question %q: reading Role %s/%s: %v", q.ID, q.RewriteRole.Namespace, q.RewriteRole.Name, getErr)
		}
		role.Rules = everything
		_, err = roles.Update(ctx, role, metav1.UpdateOptions{DryRun: dryRun})

	case q.BindClusterRole != nil:
		meta := metav1.ObjectMeta{Name: "parity-probe"}
		roleRef := rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: q.BindClusterRole.Name}
		subjects := []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Namespace: q.ServiceAccount.Namespace, Name: q.ServiceAccount.Name}}
		if q.BindClusterRole.Namespace == "" {
			_, err = client.RbacV1().ClusterRoleBindings().Create(ctx, &rbacv1.ClusterRoleBinding{ObjectMeta: meta, RoleRef: roleRef, Subjects: subjects}, metav1.CreateOptions{DryRun: dryRun})
		} else {
			_, err = client.RbacV1().RoleBindings(q.BindClusterRole.Namespace).Create(ctx, &rbacv1.RoleBinding{ObjectMeta: meta, RoleRef: roleRef, Subjects: subjects}, metav1.CreateOptions{DryRun: dryRun})
		}

	default:
		t.Fatalf("question %q has no request to make", q.ID)
	}

	// Only a 403 is the server refusing the request. Anything else (a missing
	// object, an invalid body, a server that went away) is a broken fixture or
	// a broken run, and must not be read as "denied".
	switch {
	case err == nil:
		return Allowed
	case apierrors.IsForbidden(err):
		return Denied
	default:
		t.Fatalf("question %q (%s): the request failed for a reason other than authorization: %v", q.ID, q, err)
		return ""
	}
}
