package opaprocessor

import (
	"fmt"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/pkg/securityexception"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
)

// capturingRecorder records every Eventf call's object argument, so a test can
// assert on which object an event was attached to - something record.FakeRecorder's
// plain "type reason message" string channel can't express.
type capturingRecorder struct {
	events []capturedEvent
}

type capturedEvent struct {
	object    runtime.Object
	eventtype string
	reason    string
	message   string
}

func (r *capturingRecorder) Event(object runtime.Object, eventtype, reason, message string) {
	r.events = append(r.events, capturedEvent{object, eventtype, reason, message})
}

func (r *capturingRecorder) Eventf(object runtime.Object, eventtype, reason, messageFmt string, args ...interface{}) {
	r.Event(object, eventtype, reason, fmt.Sprintf(messageFmt, args...))
}

func (r *capturingRecorder) AnnotatedEventf(object runtime.Object, _ map[string]string, eventtype, reason, messageFmt string, args ...interface{}) {
	r.Eventf(object, eventtype, reason, messageFmt, args...)
}

func TestEmitExceptionMatchEvents(t *testing.T) {
	resourceJSON := []byte(`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"nginx-frontend","namespace":"production"}}`)
	resource, err := workloadinterface.NewWorkload(resourceJSON)
	if err != nil {
		t.Fatalf("failed to create workload: %v", err)
	}

	crdException := armotypes.PostureExceptionPolicy{
		PortalBase: armotypes.PortalBase{
			Attributes: securityexception.CRDReferenceAttributes(securityexception.CRDReference{
				Kind:      "SecurityException",
				Name:      "nginx-exceptions",
				Namespace: "production",
			}),
		},
	}

	tests := []struct {
		name            string
		exceptions      []armotypes.PostureExceptionPolicy
		expectEvent     bool
		expectedMessage string
	}{
		{
			name:            "event emitted on match",
			exceptions:      []armotypes.PostureExceptionPolicy{crdException},
			expectEvent:     true,
			expectedMessage: "Matched control C-0034 on Deployment/nginx-frontend in namespace production",
		},
		{
			// Regression for issue-3369: a file/cloud-sourced exception (no CRD
			// attributes) used to be silently skipped. It must now still emit an
			// event, attached to the scanned resource itself.
			name:            "event emitted on non-crd exception, attached to the resource",
			exceptions:      []armotypes.PostureExceptionPolicy{{}},
			expectEvent:     true,
			expectedMessage: "Matched control C-0034 on Deployment/nginx-frontend in namespace production",
		},
		{
			name:        "no event on no match",
			exceptions:  nil,
			expectEvent: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := record.NewFakeRecorder(1)
			opap := &OPAProcessor{exceptionEventRecorder: recorder}

			result := resourcesresults.Result{
				AssociatedControls: []resourcesresults.ResourceAssociatedControl{
					{
						ControlID: "C-0034",
						ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
							{Exception: tt.exceptions},
						},
					},
				},
			}

			opap.emitExceptionMatchEvents(resource, result)

			select {
			case got := <-recorder.Events:
				if !tt.expectEvent {
					t.Fatalf("unexpected event: %s", got)
				}
				assert.Equal(t, "Normal ExceptionMatched "+tt.expectedMessage, got)
			case <-time.After(100 * time.Millisecond):
				if tt.expectEvent {
					t.Fatalf("expected an event but none was recorded")
				}
			}
		})
	}
}

// Regression for issue-3369: a non-CRD exception's event must be attached to
// the scanned resource itself, since it has no CRD instance of its own.
func TestEmitExceptionMatchEvents_NonCRDExceptionAttachesToScannedResource(t *testing.T) {
	resourceJSON := []byte(`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"nginx-frontend","namespace":"production"}}`)
	resource, err := workloadinterface.NewWorkload(resourceJSON)
	require.NoError(t, err)

	recorder := &capturingRecorder{}
	opap := &OPAProcessor{exceptionEventRecorder: recorder}

	result := resourcesresults.Result{
		AssociatedControls: []resourcesresults.ResourceAssociatedControl{
			{
				ControlID: "C-0034",
				ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
					{Exception: []armotypes.PostureExceptionPolicy{{}}}, // no CRD attributes
				},
			},
		},
	}

	opap.emitExceptionMatchEvents(resource, result)

	require.Len(t, recorder.events, 1)
	obj, ok := recorder.events[0].object.(*unstructured.Unstructured)
	require.True(t, ok, "event object must be an *unstructured.Unstructured")
	assert.Equal(t, "Deployment", obj.GetKind())
	assert.Equal(t, "nginx-frontend", obj.GetName())
	assert.Equal(t, "production", obj.GetNamespace())
}

// A CRD-backed and a file/cloud-backed exception matching the same control on
// the same resource use different dedup keys (crd/... vs resource/...), so
// both must emit their own event rather than one being silently deduped
// against the other.
func TestEmitExceptionMatchEvents_CRDAndNonCRDExceptionsBothEmit(t *testing.T) {
	resourceJSON := []byte(`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"nginx-frontend","namespace":"production"}}`)
	resource, err := workloadinterface.NewWorkload(resourceJSON)
	require.NoError(t, err)

	crdException := armotypes.PostureExceptionPolicy{
		PortalBase: armotypes.PortalBase{
			Attributes: securityexception.CRDReferenceAttributes(securityexception.CRDReference{
				Kind:      "SecurityException",
				Name:      "nginx-exceptions",
				Namespace: "production",
			}),
		},
	}
	fileException := armotypes.PostureExceptionPolicy{}

	recorder := &capturingRecorder{}
	opap := &OPAProcessor{exceptionEventRecorder: recorder}

	result := resourcesresults.Result{
		AssociatedControls: []resourcesresults.ResourceAssociatedControl{
			{
				ControlID: "C-0034",
				ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
					{Exception: []armotypes.PostureExceptionPolicy{crdException, fileException}},
				},
			},
		},
	}

	opap.emitExceptionMatchEvents(resource, result)

	require.Len(t, recorder.events, 2, "the CRD-backed and file-backed exceptions must each emit their own event")

	var sawCRDObject, sawResourceObject bool
	for _, e := range recorder.events {
		obj, ok := e.object.(*unstructured.Unstructured)
		require.True(t, ok)
		switch obj.GetKind() {
		case "SecurityException":
			sawCRDObject = true
			assert.Equal(t, "nginx-exceptions", obj.GetName())
		case "Deployment":
			sawResourceObject = true
			assert.Equal(t, "nginx-frontend", obj.GetName())
		default:
			t.Fatalf("unexpected event object kind %q", obj.GetKind())
		}
	}
	assert.True(t, sawCRDObject, "expected one event attached to the SecurityException CRD")
	assert.True(t, sawResourceObject, "expected one event attached to the scanned resource")
}
