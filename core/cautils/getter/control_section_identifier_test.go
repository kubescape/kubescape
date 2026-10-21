package getter

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/regolibrary/v2/gitregostore"
	"github.com/stretchr/testify/require"
)

// A control's framework section number (e.g. "CIS-3.1.1") lives in the legacy
// "id" field, and --include-controls/--skip-controls/--exclude-controls
// resolve it. GetControl, which backs `scan controls` and scan_controls, must
// resolve the same identifiers.
func sectionTestControls() []reporthandling.Control {
	return []reporthandling.Control{
		{ControlID: "C-0286", Control_ID: "CIS-3.1.1"},
		{ControlID: "C-0287", Control_ID: "CIS-3.1.2"},
		{ControlID: "C-0012"},
	}
}

func writePolicyFile(t *testing.T, dir, name string, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, b, 0o600))
	return path
}

func TestLoadPolicyGetControlSectionIdentifier(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	fw := writePolicyFile(t, dir, "fw.json", reporthandling.Framework{
		PortalBase: portalBase("cis"), Controls: sectionTestControls(),
	})

	tests := []struct {
		name, id, want string
	}{
		{"canonical id", "C-0286", "C-0286"},
		{"canonical id, other case", "c-0286", "C-0286"},
		{"section id", "CIS-3.1.1", "C-0286"},
		{"section id, other case", "cis-3.1.2", "C-0287"},
		{"section id, surrounding whitespace", "  CIS-3.1.1 ", "C-0286"},
		{"control without a section id", "C-0012", "C-0012"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl, err := NewLoadPolicy([]string{fw}).GetControl(tt.id)
			require.NoError(t, err)
			require.Equal(t, tt.want, ctrl.ControlID)
		})
	}

	t.Run("unknown id", func(t *testing.T) {
		t.Parallel()
		ctrl, err := NewLoadPolicy([]string{fw}).GetControl("CIS-9.9.9")
		require.ErrorIs(t, err, ErrControlNotMatching)
		require.Nil(t, ctrl)
	})
	t.Run("empty and whitespace-only id", func(t *testing.T) {
		t.Parallel()
		for _, id := range []string{"", "   "} {
			ctrl, err := NewLoadPolicy([]string{fw}).GetControl(id)
			require.ErrorIs(t, err, ErrIDRequired, "id %q", id)
			require.Nil(t, ctrl)
		}
	})
	t.Run("a control descriptor file is matched by section id", func(t *testing.T) {
		t.Parallel()
		f := writePolicyFile(t, dir, "ctrl.json", reporthandling.Control{ControlID: "C-0289", Control_ID: "CIS-5.5.1"})
		ctrl, err := NewLoadPolicy([]string{f}).GetControl("cis-5.5.1")
		require.NoError(t, err)
		require.Equal(t, "C-0289", ctrl.ControlID)
	})
}

func TestLoadPolicyGetControlAmbiguousSectionIdentifier(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	a := writePolicyFile(t, dir, "a.json", reporthandling.Framework{
		PortalBase: portalBase("a"), Controls: []reporthandling.Control{{ControlID: "C-0001", Control_ID: "X-1"}},
	})
	b := writePolicyFile(t, dir, "b.json", reporthandling.Framework{
		PortalBase: portalBase("b"), Controls: []reporthandling.Control{{ControlID: "C-0002", Control_ID: "x-1"}},
	})

	t.Run("a section id shared by two different controls is refused", func(t *testing.T) {
		t.Parallel()
		ctrl, err := NewLoadPolicy([]string{a, b}).GetControl("X-1")
		require.ErrorIs(t, err, ErrControlAmbiguous)
		require.Contains(t, err.Error(), "C-0001")
		require.Contains(t, err.Error(), "C-0002")
		require.Nil(t, ctrl)
	})
	t.Run("the same control repeated across frameworks is not ambiguous", func(t *testing.T) {
		t.Parallel()
		ctrl, err := NewLoadPolicy([]string{a, a}).GetControl("X-1")
		require.NoError(t, err)
		require.Equal(t, "C-0001", ctrl.ControlID)
	})
	t.Run("a canonical id wins over another control's section id", func(t *testing.T) {
		t.Parallel()
		f := writePolicyFile(t, dir, "c.json", reporthandling.Framework{
			PortalBase: portalBase("c"), Controls: []reporthandling.Control{
				{ControlID: "C-0003", Control_ID: "C-0004"},
				{ControlID: "C-0004"},
			},
		})
		ctrl, err := NewLoadPolicy([]string{f}).GetControl("C-0004")
		require.NoError(t, err)
		require.Equal(t, "C-0004", ctrl.ControlID)
	})
}

func TestDownloadReleasedPolicyGetControlSectionIdentifier(t *testing.T) {
	t.Parallel()
	newPolicy := func(controls []reporthandling.Control) *DownloadReleasedPolicy {
		p := NewDownloadReleasedPolicy()
		p.gs = &gitregostore.GitRegoStore{Controls: controls}
		return p
	}

	tests := []struct{ name, id, want string }{
		{"canonical id", "C-0286", "C-0286"},
		{"canonical id, other case", "c-0286", "C-0286"},
		{"section id", "CIS-3.1.1", "C-0286"},
		{"section id, other case and whitespace", " cis-3.1.2 ", "C-0287"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl, err := newPolicy(sectionTestControls()).GetControl(tt.id)
			require.NoError(t, err)
			require.Equal(t, tt.want, ctrl.ControlID)
		})
	}

	t.Run("unknown id is reported as not found", func(t *testing.T) {
		t.Parallel()
		_, err := newPolicy(sectionTestControls()).GetControl("CIS-9.9.9")
		require.ErrorContains(t, err, "not found")
	})
	t.Run("empty and whitespace-only id", func(t *testing.T) {
		t.Parallel()
		for _, id := range []string{"", "  "} {
			_, err := newPolicy(sectionTestControls()).GetControl(id)
			require.ErrorIs(t, err, ErrIDRequired, "id %q", id)
		}
	})
	t.Run("ambiguous section id is refused", func(t *testing.T) {
		t.Parallel()
		_, err := newPolicy([]reporthandling.Control{
			{ControlID: "C-0001", Control_ID: "X-1"},
			{ControlID: "C-0002", Control_ID: "X-1"},
		}).GetControl("x-1")
		require.ErrorIs(t, err, ErrControlAmbiguous)
	})
	t.Run("an unloaded catalog is not reported as an unknown control", func(t *testing.T) {
		t.Parallel()
		p := NewDownloadReleasedPolicy()
		p.gs = &gitregostore.GitRegoStore{} // Controls == nil: nothing loaded
		_, err := p.GetControl("CIS-3.1.1")
		require.Error(t, err)
		require.NotContains(t, err.Error(), "not found")
	})
}

func portalBase(name string) armotypes.PortalBase { return armotypes.PortalBase{Name: name} }
