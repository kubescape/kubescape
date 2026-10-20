package anonymizer

import (
	"strings"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/identifiers"
	"github.com/kubescape/kubescape/v4/core/pkg/reportcrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sensitiveException() armotypes.PostureExceptionPolicy {
	reason := "waiver for payroll-ns-7731/salary-batch-4471"
	expires := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	return armotypes.PostureExceptionPolicy{
		PortalBase: armotypes.PortalBase{
			GUID: "guid-salary-batch-4471",
			Name: "inline-apps/v1/Deployment/payroll-ns-7731/salary-batch-4471",
			Attributes: map[string]any{
				"owner": "jdoe",
			},
		},
		PolicyType: "postureExceptionPolicy",
		Actions:    []armotypes.PostureExceptionPolicyActions{armotypes.AlertOnly},
		Resources: []identifiers.PortalDesignator{{
			DesignatorType: identifiers.DesignatorAttributes,
			Attributes:     map[string]string{"name": "salary-batch-4471", "namespace": "payroll-ns-7731"},
		}},
		PosturePolicies: []armotypes.PosturePolicy{{ControlID: "C-0057"}},
		Reason:          &reason,
		ExpirationDate:  &expires,
		CreatedBy:       "jdoe",
	}
}

func TestExceptionTransformer_RemovesIdentifiersAndKeepsStatusInputs(t *testing.T) {
	encryptionKey, err := reportcrypto.GenerateDEK()
	require.NoError(t, err)
	key, err := reportcrypto.NewReportKey(encryptionKey)
	require.NoError(t, err)

	transformers := map[string]Transformer{
		"hide":    NewMappingTransformer(),
		"encrypt": NewEncryptionTransformer(key),
	}

	for name, transformer := range transformers {
		t.Run(name, func(t *testing.T) {
			original := sensitiveException()
			out, err := newExceptionTransformer(transformer).policies([]armotypes.PostureExceptionPolicy{original})
			require.NoError(t, err)
			require.Len(t, out, 1)

			for _, field := range []string{out[0].Name, out[0].GUID, *out[0].Reason, out[0].CreatedBy} {
				for _, secret := range []string{"payroll", "salary", "jdoe", "4471", "7731"} {
					assert.False(t, strings.Contains(field, secret), "%q kept in %q", secret, field)
				}
			}
			assert.Empty(t, out[0].Resources, "designators spell out the matched names")
			assert.Empty(t, out[0].Attributes)
			assert.Nil(t, out[0].ObjectSelector)

			// What decides the rule's status and the report's audit fields survives.
			assert.Equal(t, original.Actions, out[0].Actions)
			assert.Equal(t, original.PosturePolicies, out[0].PosturePolicies)
			assert.Equal(t, original.ExpirationDate, out[0].ExpirationDate)
			assert.True(t, out[0].IsAlertOnly())

			// The input is untouched.
			assert.Contains(t, original.Name, "salary-batch-4471")
			assert.Contains(t, *original.Reason, "payroll-ns-7731")
		})
	}
}

// One exception attached to several rules must come out as one value even with a
// transformer that randomizes, or readers would count it more than once.
func TestExceptionTransformer_SameExceptionTransformsIdentically(t *testing.T) {
	encryptionKey, err := reportcrypto.GenerateDEK()
	require.NoError(t, err)
	key, err := reportcrypto.NewReportKey(encryptionKey)
	require.NoError(t, err)

	et := newExceptionTransformer(NewEncryptionTransformer(key))
	first, err := et.policies([]armotypes.PostureExceptionPolicy{sensitiveException()})
	require.NoError(t, err)
	second, err := et.policies([]armotypes.PostureExceptionPolicy{sensitiveException()})
	require.NoError(t, err)
	assert.Equal(t, first[0].Name, second[0].Name)
	assert.Equal(t, first[0].GUID, second[0].GUID)
	assert.Equal(t, *first[0].Reason, *second[0].Reason)
}

func TestExceptionTransformer_EmptyFieldsStayEmpty(t *testing.T) {
	out, err := newExceptionTransformer(NewMappingTransformer()).policies([]armotypes.PostureExceptionPolicy{{}})
	require.NoError(t, err)
	assert.Empty(t, out[0].Name)
	assert.Empty(t, out[0].GUID)
	assert.Nil(t, out[0].Reason)

	none, err := newExceptionTransformer(NewMappingTransformer()).policies(nil)
	require.NoError(t, err)
	assert.Empty(t, none)
}
