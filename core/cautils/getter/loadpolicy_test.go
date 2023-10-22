package getter

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/kubescape/v3/internal/testutils"
	"github.com/stretchr/testify/require"
)

func MockNewLoadPolicy() *LoadPolicy {
	return &LoadPolicy{
		filePaths: []string{""},
	}
}

func TestLoadPolicy(t *testing.T) {
	t.Parallel()

	const (
		testFramework = "MITRE"
		testControl   = "C-0053"
	)

	t.Run("with GetFramework", func(t *testing.T) {
		t.Run("should retrieve named framework", func(t *testing.T) {
			t.Parallel()

			p := NewLoadPolicy([]string{testFrameworkFile(testFramework)})
			fw, err := p.GetFramework(testFramework)
			require.NoError(t, err)
			require.NotNil(t, fw)

			require.Equal(t, testFramework, fw.Name)
		})

		t.Run("should fail to retrieve framework", func(t *testing.T) {
			t.Parallel()

			p := NewLoadPolicy([]string{testFrameworkFile(testFramework)})
			fw, err := p.GetFramework("wrong")
			require.Error(t, err)
			require.Nil(t, fw)
		})

		t.Run("edge case: should error on empty framework", func(t *testing.T) {
			t.Parallel()

			p := NewLoadPolicy([]string{testFrameworkFile(testFramework)})
			fw, err := p.GetFramework("")
			require.ErrorIs(t, err, ErrNameRequired)
			require.Nil(t, fw)
		})

		t.Run("edge case: corrupted json", func(t *testing.T) {
			t.Parallel()

			const invalidFramework = "invalid-fw"
			p := NewLoadPolicy([]string{testFrameworkFile(invalidFramework)})
			fw, err := p.GetFramework(invalidFramework)
			require.Error(t, err)
			require.Nil(t, fw)
		})

		t.Run("edge case: missing json", func(t *testing.T) {
			t.Parallel()

			const invalidFramework = "nowheretobefound"
			p := NewLoadPolicy([]string{testFrameworkFile(invalidFramework)})
			_, err := p.GetFramework(invalidFramework)
			require.Error(t, err)
		})
	})

	t.Run("with GetControl", func(t *testing.T) {
		t.Run("should retrieve named control from framework", func(t *testing.T) {
			t.Parallel()

			const (
				expectedControlName = "Access container service account"
			)
			p := NewLoadPolicy([]string{testFrameworkFile(testFramework)})
			ctrl, err := p.GetControl(testControl)
			require.NoError(t, err)
			require.NotNil(t, ctrl)

			require.Equal(t, testControl, ctrl.ControlID)
			require.Equal(t, expectedControlName, ctrl.Name)
		})

		t.Run("with single control descriptor", func(t *testing.T) {
			const (
				singleControl       = "C-0001"
				expectedControlName = "Forbidden Container Registries"
			)

			t.Run("should retrieve named control from control descriptor", func(t *testing.T) {
				t.Parallel()

				p := NewLoadPolicy([]string{testFrameworkFile(singleControl)})
				ctrl, err := p.GetControl(singleControl)
				require.NoError(t, err)
				require.NotNil(t, ctrl)

				require.Equal(t, singleControl, ctrl.ControlID)
				require.Equal(t, expectedControlName, ctrl.Name)
			})

			t.Run("should fail to retrieve named control from control descriptor", func(t *testing.T) {
				t.Parallel()

				p := NewLoadPolicy([]string{testFrameworkFile(singleControl)})
				ctrl, err := p.GetControl("wrong")
				require.Error(t, err)
				require.Nil(t, ctrl)
			})
		})

		t.Run("with framework descriptor", func(t *testing.T) {
			t.Run("should fail to retrieve named control", func(t *testing.T) {
				t.Parallel()

				const testControl = "wrong"
				p := NewLoadPolicy([]string{testFrameworkFile(testFramework)})
				ctrl, err := p.GetControl(testControl)
				require.ErrorIs(t, err, ErrControlNotMatching)
				require.Nil(t, ctrl)
			})
		})

		t.Run("edge case: corrupted json", func(t *testing.T) {
			t.Parallel()

			const invalidControl = "invalid-fw"
			p := NewLoadPolicy([]string{testFrameworkFile(invalidControl)})
			_, err := p.GetControl(invalidControl)
			require.Error(t, err)
		})

		t.Run("edge case: missing json", func(t *testing.T) {
			t.Parallel()

			const invalidControl = "nowheretobefound"
			p := NewLoadPolicy([]string{testFrameworkFile(invalidControl)})
			_, err := p.GetControl(invalidControl)
			require.Error(t, err)
		})

		t.Run("edge case: should error on empty control", func(t *testing.T) {
			t.Parallel()

			p := NewLoadPolicy([]string{testFrameworkFile(testFramework)})
			ctrl, err := p.GetControl("")
			require.ErrorIs(t, err, ErrIDRequired)
			require.Nil(t, ctrl)
		})
	})

	t.Run("with ListFrameworks", func(t *testing.T) {
		t.Run("should return all frameworks in the policy path", func(t *testing.T) {
			t.Parallel()

			const (
				extraFramework = "NSA"
				attackTracks   = "attack-tracks"
			)
			p := NewLoadPolicy([]string{
				testFrameworkFile(testFramework),
				testFrameworkFile(extraFramework),
				testFrameworkFile(extraFramework), // should  be deduped
				testFrameworkFile(attackTracks),   // should be ignored
			})
			fws, err := p.ListFrameworks()
			require.NoError(t, err)
			require.Len(t, fws, 2)

			require.Equal(t, testFramework, fws[0])
			require.Equal(t, extraFramework, fws[1])
		})

		t.Run("should not return an empty framework", func(t *testing.T) {
			t.Parallel()

			const (
				extraFramework = "NSA"
				attackTracks   = "attack-tracks"
				controlsInputs = "controls-inputs"
			)
			p := NewLoadPolicy([]string{
				testFrameworkFile(testFramework),
				testFrameworkFile(extraFramework),
				testFrameworkFile(attackTracks),   // should be ignored
				testFrameworkFile(controlsInputs), // should be ignored
			})
			fws, err := p.ListFrameworks()
			require.NoError(t, err)
			require.Len(t, fws, 2)
			require.NotContains(t, fws, "")

			require.Equal(t, testFramework, fws[0])
			require.Equal(t, extraFramework, fws[1])
		})

		t.Run("should fail on file error", func(t *testing.T) {
			t.Parallel()

			const (
				extraFramework = "NSA"
				nowhere        = "nowheretobeseen"
			)
			p := NewLoadPolicy([]string{
				testFrameworkFile(testFramework),
				testFrameworkFile(extraFramework),
				testFrameworkFile(nowhere), // should raise an error
			})
			fws, err := p.ListFrameworks()
			require.Error(t, err)
			require.Nil(t, fws)
		})
	})

	t.Run("edge case: policy without path", func(t *testing.T) {
		t.Parallel()

		p := NewLoadPolicy([]string{})
		require.Empty(t, p.filePath())
	})

	t.Run("with GetFrameworks", func(t *testing.T) {
		const extraFramework = "NSA"

		t.Run("should return all configured frameworks", func(t *testing.T) {
			t.Parallel()

			p := NewLoadPolicy([]string{
				testFrameworkFile(testFramework),
				testFrameworkFile(extraFramework),
			})
			fws, err := p.GetFrameworks()
			require.NoError(t, err)
			require.Len(t, fws, 2)

			require.Equal(t, testFramework, fws[0].Name)
			require.Equal(t, extraFramework, fws[1].Name)
		})

		t.Run("should return dedupe configured frameworks", func(t *testing.T) {
			t.Parallel()

			const attackTracks = "attack-tracks"
			p := NewLoadPolicy([]string{
				testFrameworkFile(testFramework),
				testFrameworkFile(extraFramework),
				testFrameworkFile(extraFramework),
				testFrameworkFile(attackTracks), // should be ignored
			})
			fws, err := p.GetFrameworks()
			require.NoError(t, err)
			require.Len(t, fws, 2)

			require.Equal(t, testFramework, fws[0].Name)
			require.Equal(t, extraFramework, fws[1].Name)
		})
	})

	t.Run("with ListControls", func(t *testing.T) {
		t.Run("should return controls", func(t *testing.T) {
			t.Parallel()

			p := NewLoadPolicy([]string{testFrameworkFile(testFramework)})
			controlIDs, err := p.ListControls()
			require.NoError(t, err)
			require.Greater(t, len(controlIDs), 0)
			require.Equal(t, testControl, controlIDs[0])
		})
	})

	t.Run("with GetAttackTracks", func(t *testing.T) {
		t.Run("should return attack tracks", func(t *testing.T) {
			t.Parallel()

			const attackTracks = "attack-tracks"
			p := NewLoadPolicy([]string{testFrameworkFile(attackTracks)})
			tracks, err := p.GetAttackTracks()
			require.NoError(t, err)
			require.Greater(t, len(tracks), 0)

			for _, track := range tracks {
				require.Equal(t, "AttackTrack", track.Kind)
			}
		})

		t.Run("edge case: corrupted json", func(t *testing.T) {
			t.Parallel()

			const invalidTracks = "invalid-fw"
			p := NewLoadPolicy([]string{testFrameworkFile(invalidTracks)})
			_, err := p.GetAttackTracks()
			require.Error(t, err)
		})

		t.Run("edge case: missing json", func(t *testing.T) {
			t.Parallel()

			const invalidTracks = "nowheretobefound"
			p := NewLoadPolicy([]string{testFrameworkFile(invalidTracks)})
			_, err := p.GetAttackTracks()
			require.Error(t, err)
		})
	})

	t.Run("with GetControlsInputs", func(t *testing.T) {
		const cluster = "dummy" // unused parameter at the moment

		t.Run("should return control inputs for a cluster", func(t *testing.T) {
			t.Parallel()

			fixture, expected := writeTempJSONControlInputs(t)
			t.Cleanup(func() {
				_ = os.Remove(fixture)
			})

			p := NewLoadPolicy([]string{fixture})
			inputs, err := p.GetControlsInputs(cluster)
			require.NoError(t, err)
			require.EqualValues(t, expected, inputs)
		})

		t.Run("edge case: corrupted json", func(t *testing.T) {
			t.Parallel()

			const invalidInputs = "invalid-fw"
			p := NewLoadPolicy([]string{testFrameworkFile(invalidInputs)})
			_, err := p.GetControlsInputs(cluster)
			require.Error(t, err)
		})

		t.Run("edge case: missing json", func(t *testing.T) {
			t.Parallel()

			const invalidInputs = "nowheretobefound"
			p := NewLoadPolicy([]string{testFrameworkFile(invalidInputs)})
			_, err := p.GetControlsInputs(cluster)
			require.Error(t, err)
		})
	})

	t.Run("with GetExceptions", func(t *testing.T) {
		const cluster = "dummy" // unused parameter at the moment

		t.Run("should return exceptions", func(t *testing.T) {
			t.Parallel()

			const exceptions = "exceptions"

			p := NewLoadPolicy([]string{testFrameworkFile(exceptions)})
			exceptionPolicies, err := p.GetExceptions(cluster)
			require.NoError(t, err)

			require.Greater(t, len(exceptionPolicies), 0)
			t.Logf("len=%d", len(exceptionPolicies))
			for _, policy := range exceptionPolicies {
				require.NotEmpty(t, policy.Name)
			}
		})

		t.Run("edge case: corrupted json", func(t *testing.T) {
			t.Parallel()

			const invalidInputs = "invalid-fw"
			p := NewLoadPolicy([]string{testFrameworkFile(invalidInputs)})
			_, err := p.GetExceptions(cluster)
			require.Error(t, err)
		})

		t.Run("edge case: missing json", func(t *testing.T) {
			t.Parallel()

			const invalidInputs = "nowheretobefound"
			p := NewLoadPolicy([]string{testFrameworkFile(invalidInputs)})
			_, err := p.GetExceptions(cluster)
			require.Error(t, err)
		})
	})
}

func testFrameworkFile(framework string) string {
	return filepath.Join(testutils.CurrentDir(), "testdata", fmt.Sprintf("%s.json", framework))
}

func writeTempJSONControlInputs(t testing.TB) (string, map[string][]string) {
	fileName := testFrameworkFile("control-inputs")
	mock := map[string][]string{
		"key1": {
			"val1", "val2",
		},
		"key2": {
			"val3", "val4",
		},
	}

	buf, err := json.Marshal(mock)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(fileName, buf, 0600))

	return fileName, mock
}
