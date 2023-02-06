package getter

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReleasedPolicy(t *testing.T) {
	t.Parallel()

	p := NewDownloadReleasedPolicy()

	t.Run("should initialize objects", func(t *testing.T) {
		t.Parallel()

		require.NoError(t, p.SetRegoObjects())

		t.Run("with ListControls", func(t *testing.T) {
			t.Parallel()

			controlIDs, err := p.ListControls()
			require.NoError(t, err)
			require.NotEmpty(t, controlIDs)

			sampleSize := min(len(controlIDs), 10)

			for _, toPin := range controlIDs[:sampleSize] {
				// Example of a returned "ID": `C-0154|Ensure_that_the_--client-cert-auth_argument_is_set_to_true|`
				controlString := toPin
				parts := strings.Split(controlString, "|")
				controlID := parts[0]

				t.Run(fmt.Sprintf("with GetControl(%q)", controlID), func(t *testing.T) {
					t.Parallel()

					ctrl, err := p.GetControl(controlID)
					require.NoError(t, err)
					require.NotEmpty(t, ctrl)
					require.Equal(t, controlID, ctrl.ControlID)
				})
			}

			t.Run("with unknown GetControl()", func(t *testing.T) {
				t.Parallel()

				ctrl, err := p.GetControl("zork")
				require.Error(t, err)
				require.Nil(t, ctrl)
			})
		})

		t.Run("with GetFrameworks", func(t *testing.T) {
			t.Parallel()

			frameworks, err := p.GetFrameworks()
			require.NoError(t, err)
			require.NotEmpty(t, frameworks)

			for _, toPin := range frameworks {
				framework := toPin
				require.NotEmpty(t, framework)
				require.NotEmpty(t, framework.Name)

				t.Run(fmt.Sprintf("with GetFramework(%q)", framework.Name), func(t *testing.T) {
					t.Parallel()

					fw, err := p.GetFramework(framework.Name)
					require.NoError(t, err)
					require.NotNil(t, fw)

					require.EqualValues(t, framework, *fw)
				})
			}

			t.Run("with unknown GetFramework()", func(t *testing.T) {
				t.Parallel()

				ctrl, err := p.GetFramework("zork")
				require.Error(t, err)
				require.Nil(t, ctrl)
			})

			t.Run("with ListFrameworks", func(t *testing.T) {
				t.Parallel()

				frameworkIDs, err := p.ListFrameworks()
				require.NoError(t, err)
				require.NotEmpty(t, frameworkIDs)

				require.Len(t, frameworkIDs, len(frameworks))
			})

		})

		t.Run("with GetControlsInput", func(t *testing.T) {
			t.Parallel()

			controlInputs, err := p.GetControlsInputs("") // NOTE: cluster name currently unused
			require.NoError(t, err)
			require.NotEmpty(t, controlInputs)
		})

		t.Run("with GetAttackTracks", func(t *testing.T) {
			t.Parallel()

			attackTracks, err := p.GetAttackTracks()
			require.NoError(t, err)
			require.NotEmpty(t, attackTracks)
		})

		t.Run("with GetExceptions", func(t *testing.T) {
			t.Parallel()

			exceptions, err := p.GetExceptions("") // NOTE: cluster name currently unused
			require.NoError(t, err)
			require.NotEmpty(t, exceptions)
		})
	})
}

func min(a, b int) int {
	if a > b {
		return b
	}

	return a
}
