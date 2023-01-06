package getter

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func MockNewLoadPolicy() *LoadPolicy {
	return &LoadPolicy{
		filePaths: []string{""},
	}
}

func testFrameworkFile(framework string) string {
	return filepath.Join(".", "testdata", fmt.Sprintf("%s.json", framework))
}

func TestLoadPolicy(t *testing.T) {
	t.Parallel()

	const testFramework = "MITRE"

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

		t.Run("edge case: should return empty framework", func(t *testing.T) {
			// NOTE(fredbi): this edge case corresponds to the original working of GetFramework.
			// IMHO, this is a bad request call and it should return an error.
			t.Parallel()

			p := NewLoadPolicy([]string{testFrameworkFile(testFramework)})
			fw, err := p.GetFramework("")
			require.NoError(t, err)
			require.NotNil(t, fw)
			require.Empty(t, *fw)
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
		t.Run("should retrieve named control", func(t *testing.T) {
			t.Parallel()

			const (
				testControl         = "C-0053"
				expectedControlName = "Access container service account"
			)
			p := NewLoadPolicy([]string{testFrameworkFile(testFramework)})
			ctrl, err := p.GetControl(testControl)
			require.NoError(t, err)
			require.NotNil(t, ctrl)

			require.Equal(t, testControl, ctrl.ControlID)
			require.Equal(t, expectedControlName, ctrl.Name)
		})

		t.Run("should fail to retrieve named control", func(t *testing.T) {
			// NOTE(fredbi): IMHO, this case should bubble up an error
			t.Parallel()

			const testControl = "wrong"
			p := NewLoadPolicy([]string{testFrameworkFile(testFramework)})
			ctrl, err := p.GetControl(testControl)
			require.NoError(t, err)
			require.NotNil(t, ctrl) // no error, but still don't get the requested control...
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

		t.Run("edge case: should return empty control", func(t *testing.T) {
			// NOTE(fredbi): this edge case corresponds to the original working of GetFramework.
			// IMHO, this is a bad request call and it should return an error.
			t.Parallel()

			p := NewLoadPolicy([]string{testFrameworkFile(testFramework)})
			ctrl, err := p.GetControl("")
			require.NoError(t, err)
			require.NotNil(t, ctrl)
		})
	})

	t.Run("ListFrameworks should return all frameworks in the policy path", func(t *testing.T) {
		t.Parallel()

		const extraFramework = "NSA"
		p := NewLoadPolicy([]string{
			testFrameworkFile(testFramework),
			testFrameworkFile(extraFramework),
		})
		fws, err := p.ListFrameworks()
		require.NoError(t, err)
		require.Len(t, fws, 2)

		require.Equal(t, testFramework, fws[0])
		require.Equal(t, extraFramework, fws[1])
	})

	t.Run("edge case: policy without path", func(t *testing.T) {
		t.Parallel()

		p := NewLoadPolicy([]string{})
		require.Empty(t, p.filePath())
	})

	t.Run("GetFrameworks is currently stubbed", func(t *testing.T) {
		t.Parallel()

		p := NewLoadPolicy([]string{testFrameworkFile(testFramework)})
		fws, err := p.GetFrameworks()
		require.NoError(t, err)
		require.Empty(t, fws)
	})

	t.Run("ListControls is currently unsupported", func(t *testing.T) {
		t.Parallel()

		p := NewLoadPolicy([]string{testFrameworkFile(testFramework)})
		_, err := p.ListControls()
		require.Error(t, err)
	})
}
