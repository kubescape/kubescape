package opaprocessor

import (
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/pkg/securityexception"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/assert"
	"k8s.io/client-go/tools/record"
)

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
			name:        "no event on non-crd exception",
			exceptions:  []armotypes.PostureExceptionPolicy{{}},
			expectEvent: false,
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
