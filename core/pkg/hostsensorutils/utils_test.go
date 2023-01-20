package hostsensorutils

import (
	"errors"
	"fmt"
	"testing"

	"github.com/kubescape/opa-utils/objectsenvelopes/hostsensor"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/stretchr/testify/require"
)

func TestAddInfoToMap(t *testing.T) {
	t.Parallel()

	// NOTE: the function being tested is hard to test, because
	// the worker pool mutes most errors.
	//
	// Essentially, unless we hit some extreme edge case, we never get an error to be added to the map.
	testErr := errors.New("test error")

	for _, toPin := range []struct {
		Resource scannerResource
		Err      error
		Expected map[string]apis.StatusInfo
	}{
		{
			Resource: KubeletConfiguration,
			Err:      testErr,
			Expected: map[string]apis.StatusInfo{
				"hostdata.kubescape.cloud/v1beta0/KubeletConfiguration": {
					InnerStatus: apis.StatusSkipped,
					InnerInfo:   testErr.Error(),
				},
			},
		},
		{
			Resource: CNIInfo,
			Err:      testErr,
			Expected: map[string]apis.StatusInfo{
				"hostdata.kubescape.cloud/v1beta0/CNIInfo": {
					InnerStatus: apis.StatusSkipped,
					InnerInfo:   testErr.Error(),
				},
			},
		},
	} {
		tc := toPin

		t.Run(fmt.Sprintf("should expect a status for resource %s", tc.Resource), func(t *testing.T) {
			t.Parallel()

			result := make(map[string]apis.StatusInfo, 1)
			require.NotEmpty(t, tc.Resource.Path())
			addInfoToMap(tc.Resource, result, tc.Err)

			require.EqualValues(t, tc.Expected, result)
		})
	}

	t.Run("should panic (dev error) when resource is invalid", func(t *testing.T) {
		require.Panics(t, func() {
			scannerResource("invalid").Path()
		})

		require.Panics(t, func() {
			addInfoToMap(scannerResource("invalid"), map[string]apis.StatusInfo{}, testErr)
		})
	})
}

func TestReformatResponses(t *testing.T) {
	t.Parallel()

	t.Run("with reformat kubelet command line", func(t *testing.T) {
		t.Run("should convert command line", func(t *testing.T) {
			envelope := hostsensor.HostSensorDataEnvelope{
				Data: []byte(`abc`),
			}
			reformatKubeletCommandLine(&envelope)
			require.JSONEq(t, `{"fullCommand":"abc"}`, string(envelope.GetData()))
		})
	})

	t.Run("with reformat kubelet configurations", func(t *testing.T) {
		t.Run("should convert YAML", func(t *testing.T) {
			envelope := hostsensor.HostSensorDataEnvelope{
				Data: []byte("object:\n  key: value\n"),
			}
			require.NoError(t, reformatKubeletConfiguration(&envelope))
			require.JSONEq(t, `{"object":{"key":"value"}}`, string(envelope.GetData()))
		})

		t.Run("should error on invalid YAML", func(t *testing.T) {
			envelope := hostsensor.HostSensorDataEnvelope{
				Data: []byte("object:\n\tkey: value\n"),
			}
			require.Error(t, reformatKubeletConfiguration(&envelope))
		})
	})
}
