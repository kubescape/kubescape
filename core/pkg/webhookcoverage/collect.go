package webhookcoverage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
)

const (
	admissionGroup    = "admissionregistration.k8s.io"
	admissionVersion  = "v1"
	validatingListing = "validatingwebhookconfigurations"
	mutatingListing   = "mutatingwebhookconfigurations"
)

// ErrUnsupported reports a cluster that does not serve the webhook
// configuration API.
var ErrUnsupported = errors.New("cluster does not serve admissionregistration.k8s.io/v1 webhook configurations")

// ErrForbidden reports credentials that may not list webhook configurations.
var ErrForbidden = errors.New("not permitted to list admission webhook configurations")

// Source is the outcome of collecting one kind of webhook configuration.
// Available is the only way to tell "the cluster has none" (Available with no
// items) from "the list could not be read" (not Available, Err set): an
// unavailable list is never treated as an empty one.
type Source struct {
	Available bool
	// Err is why the list is unavailable; nil when Available.
	Err error
	// DecodeErrs name configurations that were listed but could not be
	// decoded. They are absent from the collection, so a Source with
	// DecodeErrs is available but not complete.
	DecodeErrs []error
}

// Complete reports whether every configuration of the kind was collected.
func (s Source) Complete() bool { return s.Available && len(s.DecodeErrs) == 0 }

// Collection holds the webhook configurations read from a cluster. Validating
// and mutating configurations are listed independently, so failing to read one
// kind does not hide the other.
type Collection struct {
	Validating []admissionregistrationv1.ValidatingWebhookConfiguration
	Mutating   []admissionregistrationv1.MutatingWebhookConfiguration

	ValidatingSource Source
	MutatingSource   Source
}

// Complete reports whether both kinds were collected in full.
func (c *Collection) Complete() bool {
	return c != nil && c.ValidatingSource.Complete() && c.MutatingSource.Complete()
}

// ErrDiscoveryRequired reports that no discovery client was given to confirm
// the cluster serves the webhook configuration API. Listing an API the cluster
// does not serve would be indistinguishable from a transient failure, so the
// collection is refused instead of guessed.
var ErrDiscoveryRequired = errors.New("a discovery client is required to confirm the cluster serves admission webhook configurations")

// Collect lists ValidatingWebhookConfiguration and MutatingWebhookConfiguration
// objects (admissionregistration.k8s.io/v1, GA since Kubernetes 1.16) from the
// live cluster. Both kinds are cluster-scoped. Each kind is listed
// independently and its outcome recorded on the returned Collection; a failure
// is never reported as an empty list. Configurations are returned sorted by
// name, without duplicates. Discovery is consulted first, as the other
// admission collectors do: a kind the cluster does not serve is ErrUnsupported
// on its Source, and a discovery failure is recorded on both Sources. Collect
// returns an error only when it cannot try at all (no dynamic or discovery
// client).
func Collect(ctx context.Context, k8s *k8sinterface.KubernetesApi) (*Collection, error) {
	if k8s == nil || k8s.DynamicClient == nil {
		return nil, errors.New("a dynamic client is required to list admission webhook configurations")
	}
	if k8s.DiscoveryClient == nil {
		return nil, ErrDiscoveryRequired
	}
	return collect(ctx, k8s.DynamicClient, k8s.DiscoveryClient), nil
}

// discover reports, per resource name, why it cannot be listed: nil when the
// cluster serves it.
func discover(client discovery.DiscoveryInterface) map[string]error {
	gv := schema.GroupVersion{Group: admissionGroup, Version: admissionVersion}
	resources, err := client.ServerResourcesForGroupVersion(gv.String())
	status := map[string]error{}
	for _, name := range []string{validatingListing, mutatingListing} {
		switch {
		case err != nil && apierrors.IsNotFound(err):
			status[name] = ErrUnsupported
		case err != nil:
			status[name] = fmt.Errorf("failed to discover %s: %w", gv.String(), err)
		default:
			status[name] = ErrUnsupported
		}
	}
	if err == nil && resources != nil {
		for _, r := range resources.APIResources {
			if _, ok := status[r.Name]; ok {
				status[r.Name] = nil
			}
		}
	}
	return status
}

func collect(ctx context.Context, client dynamic.Interface, disc discovery.DiscoveryInterface) *Collection {
	c := &Collection{}
	served := discover(disc)

	raw, err := listIfServed(ctx, client, validatingListing, served[validatingListing])
	if err != nil {
		c.ValidatingSource = Source{Err: err}
	} else {
		c.ValidatingSource.Available = true
		for i := range raw {
			var cfg admissionregistrationv1.ValidatingWebhookConfiguration
			if decErr := decode(raw[i].Object, &cfg); decErr != nil {
				c.ValidatingSource.DecodeErrs = append(c.ValidatingSource.DecodeErrs,
					fmt.Errorf("ValidatingWebhookConfiguration %s: %w", raw[i].GetName(), decErr))
				continue
			}
			c.Validating = append(c.Validating, cfg)
		}
		sort.SliceStable(c.Validating, func(i, j int) bool { return c.Validating[i].Name < c.Validating[j].Name })
	}

	raw, err = listIfServed(ctx, client, mutatingListing, served[mutatingListing])
	if err != nil {
		c.MutatingSource = Source{Err: err}
	} else {
		c.MutatingSource.Available = true
		for i := range raw {
			var cfg admissionregistrationv1.MutatingWebhookConfiguration
			if decErr := decode(raw[i].Object, &cfg); decErr != nil {
				c.MutatingSource.DecodeErrs = append(c.MutatingSource.DecodeErrs,
					fmt.Errorf("MutatingWebhookConfiguration %s: %w", raw[i].GetName(), decErr))
				continue
			}
			c.Mutating = append(c.Mutating, cfg)
		}
		sort.SliceStable(c.Mutating, func(i, j int) bool { return c.Mutating[i].Name < c.Mutating[j].Name })
	}
	return c
}

// listIfServed lists a resource unless discovery already said why it cannot be.
func listIfServed(ctx context.Context, client dynamic.Interface, resource string, discoveryErr error) ([]unstructured.Unstructured, error) {
	if discoveryErr != nil {
		return nil, discoveryErr
	}
	return list(ctx, client, resource)
}

// list pulls every object of one cluster-scoped resource, dropping repeats of
// a name (a configuration appearing on two pages while the list changes).
func list(ctx context.Context, client dynamic.Interface, resource string) ([]unstructured.Unstructured, error) {
	gvr := schema.GroupVersionResource{Group: admissionGroup, Version: admissionVersion, Resource: resource}

	var items []unstructured.Unstructured
	seen := map[string]struct{}{}
	listFunc := func(opts metav1.ListOptions) (string, error) {
		listed, err := client.Resource(gvr).List(ctx, opts)
		if err != nil {
			if apierrors.IsNotFound(err) {
				return "", ErrUnsupported
			}
			if apierrors.IsForbidden(err) {
				return "", fmt.Errorf("%w: %s", ErrForbidden, gvr.String())
			}
			return "", fmt.Errorf("failed to list %s: %w", gvr.String(), err)
		}
		for i := range listed.Items {
			name := listed.Items[i].GetName()
			if _, dup := seen[name]; dup {
				continue
			}
			seen[name] = struct{}{}
			items = append(items, listed.Items[i])
		}
		return listed.GetContinue(), nil
	}

	if err := getter.ListWithPagination(ctx, listFunc); err != nil {
		return nil, err
	}
	return items, nil
}

// decode converts an unstructured object into its typed shape with a JSON
// round-trip, as core/pkg/mapreconcile does.
func decode(obj map[string]any, out any) error {
	b, err := json.Marshal(obj)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}
	return nil
}
