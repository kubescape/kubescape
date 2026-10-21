package getter

import (
	"errors"
	"testing"

	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/regolibrary/v2/gitregostore"
	"github.com/stretchr/testify/require"
)

// stubControlGetter answers GetControl with a fixed outcome.
type stubControlGetter struct {
	IPolicyGetter
	control *reporthandling.Control
	err     error
}

func (s *stubControlGetter) GetControl(string) (*reporthandling.Control, error) {
	return s.control, s.err
}

func TestResolveControl(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	fw := writePolicyFile(t, dir, "fw.json", reporthandling.Framework{
		PortalBase: portalBase("cis"), Controls: sectionTestControls(),
	})
	released := func() *DownloadReleasedPolicy {
		p := NewDownloadReleasedPolicy()
		p.gs = &gitregostore.GitRegoStore{Controls: sectionTestControls()}
		return p
	}
	getters := map[string]IPolicyGetter{
		"local file":      NewLoadPolicy([]string{fw}),
		"released bundle": released(),
	}

	for name, pg := range getters {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			for id, want := range map[string]string{
				"C-0286":      "C-0286",
				" c-0286 ":    "C-0286",
				"CIS-3.1.1":   "C-0286",
				" cis-3.1.2 ": "C-0287",
				"C-0012":      "C-0012",
			} {
				control, err := ResolveControl(pg, id)
				require.NoError(t, err, "id %q", id)
				require.Equal(t, want, control.ControlID, "id %q", id)
			}
		})
		t.Run(name+" unknown", func(t *testing.T) {
			t.Parallel()
			control, err := ResolveControl(pg, "CIS-9.9.9")
			require.ErrorIs(t, err, ErrControlNotFound)
			require.NotErrorIs(t, err, ErrControlAmbiguous)
			require.Nil(t, control)
		})
	}

	t.Run("unknown keeps its message and original sentinel", func(t *testing.T) {
		t.Parallel()
		_, err := ResolveControl(NewLoadPolicy([]string{fw}), "CIS-9.9.9")
		require.ErrorIs(t, err, ErrControlNotMatching)
		require.EqualError(t, err, "controlID: CIS-9.9.9: "+ErrControlNotMatching.Error())

		_, err = ResolveControl(released(), "CIS-9.9.9")
		require.EqualError(t, err, "control 'CIS-9.9.9' not found")
	})
}

func TestResolveControlAmbiguous(t *testing.T) {
	t.Parallel()
	pg := NewDownloadReleasedPolicy()
	pg.gs = &gitregostore.GitRegoStore{Controls: []reporthandling.Control{
		{ControlID: "C-0001", Control_ID: "X-1"},
		{ControlID: "C-0002", Control_ID: "X-1"},
	}}

	_, err := ResolveControl(pg, " x-1 ")
	require.ErrorIs(t, err, ErrControlAmbiguous)
	require.NotErrorIs(t, err, ErrControlNotFound, "an ambiguous identifier is not an unknown one")

	var ambiguous *AmbiguousControlError
	require.ErrorAs(t, err, &ambiguous)
	require.Equal(t, "x-1", ambiguous.Identifier)
	require.Equal(t, []string{"C-0001", "C-0002"}, ambiguous.Matches)
	require.Contains(t, err.Error(), "C-0001, C-0002")
}

func TestResolveControlErrorsAreNotUnknownControls(t *testing.T) {
	t.Parallel()

	t.Run("empty identifier is reported as required, not as an unknown control", func(t *testing.T) {
		t.Parallel()
		fw := writePolicyFile(t, t.TempDir(), "fw.json", reporthandling.Framework{
			PortalBase: portalBase("cis"), Controls: sectionTestControls(),
		})
		for _, id := range []string{"", "  \t"} {
			_, err := ResolveControl(NewLoadPolicy([]string{fw}), id)
			require.ErrorIs(t, err, ErrIDRequired, "id %q", id)
			require.NotErrorIs(t, err, ErrControlNotFound)
		}
	})
	t.Run("a catalog failure is returned as is, even if it mentions not found", func(t *testing.T) {
		t.Parallel()
		boom := errors.New("download: bundle not found")
		_, err := ResolveControl(&stubControlGetter{err: boom}, "C-0001")
		require.ErrorIs(t, err, boom)
		require.NotErrorIs(t, err, ErrControlNotFound)
	})
	t.Run("a getter that returns neither a control nor an error reports not found", func(t *testing.T) {
		t.Parallel()
		_, err := ResolveControl(&stubControlGetter{}, "C-0001")
		require.ErrorIs(t, err, ErrControlNotFound)
	})
	t.Run("a control the getter returns is passed through", func(t *testing.T) {
		t.Parallel()
		want := &reporthandling.Control{ControlID: "C-0001"}
		got, err := ResolveControl(&stubControlGetter{control: want}, "C-0001")
		require.NoError(t, err)
		require.Same(t, want, got)
	})
}
