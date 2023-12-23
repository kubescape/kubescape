package getter

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	jsoniter "github.com/json-iterator/go"
	"github.com/kubescape/kubescape/v3/internal/testutils"
	"github.com/stretchr/testify/require"
)

func min(a, b int64) int64 {
	if a < b {
		return a
	}

	return b
}

func TestReleasedPolicy(t *testing.T) {
	t.Parallel()

	p := NewDownloadReleasedPolicy()

	t.Run("should initialize objects", func(t *testing.T) {
		t.Parallel()

		// acquire from github or from local fixture
		hydrateReleasedPolicyFromMock(t, p)

		require.NoError(t, p.SetRegoObjects())

		t.Run("with ListControls", func(t *testing.T) {
			t.Parallel()

			controlIDs, err := p.ListControls()
			require.NoError(t, err)
			require.NotEmpty(t, controlIDs)

			sampleSize := int(min(int64(len(controlIDs)), 10))

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

func hydrateReleasedPolicyFromMock(t testing.TB, p *DownloadReleasedPolicy) {
	regoFile := testRegoFile("policy")

	if _, err := os.Stat(regoFile); errors.Is(err, fs.ErrNotExist) {
		// retrieve fixture from latest released policy from github.
		//
		// NOTE: to update the mock, just delete the testdata/policy.json file and run the tests again.
		t.Logf("updating fixture file %q from github", regoFile)

		require.NoError(t, p.SetRegoObjects())
		require.NotNil(t, p.gs)

		require.NoError(t,
			SaveInFile(p.gs, regoFile),
		)

		return
	}

	// we have a mock fixture: load this rather than calling github
	t.Logf("populating rego policy from fixture file %q", regoFile)
	buf, err := os.ReadFile(regoFile)
	require.NoError(t, err)

	require.NoError(t,
		jsoniter.Unmarshal(buf, p.gs),
	)
}

func testRegoFile(framework string) string {
	return filepath.Join(testutils.CurrentDir(), "testdata", fmt.Sprintf("%s.json", framework))
}
