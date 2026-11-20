package getter

import (
	"testing"

	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/regolibrary/v2/gitregostore"
	"github.com/stretchr/testify/require"
)

// `scan control` advertises control names in its usage and its first example
// ("privileged container"), so GetControl, which backs it, has to resolve a
// control by its name as well as by its control ID or section number.
func nameTestControls() []reporthandling.Control {
	return []reporthandling.Control{
		{PortalBase: portalBase("Privileged container"), ControlID: "C-0057"},
		{PortalBase: portalBase("HostPath mount"), ControlID: "C-0048"},
		{PortalBase: portalBase("Immutable container filesystem"), ControlID: "C-0017", Control_ID: "CIS-5.2.1"},
	}
}

func TestLoadPolicyGetControlName(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	fw := writePolicyFile(t, dir, "fw.json", reporthandling.Framework{
		PortalBase: portalBase("nsa"), Controls: nameTestControls(),
	})

	tests := []struct {
		name, id, want string
	}{
		{"name", "Privileged container", "C-0057"},
		{"name, other case", "privileged container", "C-0057"},
		{"name, surrounding whitespace", "  HostPath mount ", "C-0048"},
		{"name of a control that also has a section id", "immutable container filesystem", "C-0017"},
		{"control id still works", "C-0057", "C-0057"},
		{"section id still works", "CIS-5.2.1", "C-0017"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl, err := NewLoadPolicy([]string{fw}).GetControl(tt.id)
			require.NoError(t, err)
			require.Equal(t, tt.want, ctrl.ControlID)
		})
	}

	t.Run("unknown name", func(t *testing.T) {
		t.Parallel()
		ctrl, err := NewLoadPolicy([]string{fw}).GetControl("no such control")
		require.ErrorIs(t, err, ErrControlNotMatching)
		require.Nil(t, ctrl)
	})
	t.Run("a control descriptor file is matched by name", func(t *testing.T) {
		t.Parallel()
		f := writePolicyFile(t, dir, "ctrl.json", reporthandling.Control{PortalBase: portalBase("Allow privilege escalation"), ControlID: "C-0016"})
		ctrl, err := NewLoadPolicy([]string{f}).GetControl("allow privilege escalation")
		require.NoError(t, err)
		require.Equal(t, "C-0016", ctrl.ControlID)
	})
	t.Run("a name shared by two different controls is refused", func(t *testing.T) {
		t.Parallel()
		f := writePolicyFile(t, dir, "dup.json", reporthandling.Framework{
			PortalBase: portalBase("dup"), Controls: []reporthandling.Control{
				{PortalBase: portalBase("Same name"), ControlID: "C-0101"},
				{PortalBase: portalBase("same NAME"), ControlID: "C-0102"},
			},
		})
		ctrl, err := NewLoadPolicy([]string{f}).GetControl("Same name")
		require.ErrorIs(t, err, ErrControlAmbiguous)
		require.Contains(t, err.Error(), "C-0101")
		require.Contains(t, err.Error(), "C-0102")
		require.Nil(t, ctrl)
	})
	t.Run("a control ID wins over another control's name", func(t *testing.T) {
		t.Parallel()
		f := writePolicyFile(t, dir, "idwins.json", reporthandling.Framework{
			PortalBase: portalBase("idwins"), Controls: []reporthandling.Control{
				{PortalBase: portalBase("C-0201"), ControlID: "C-0200"},
				{PortalBase: portalBase("Other"), ControlID: "C-0201"},
			},
		})
		ctrl, err := NewLoadPolicy([]string{f}).GetControl("C-0201")
		require.NoError(t, err)
		require.Equal(t, "C-0201", ctrl.ControlID)
	})
}

func TestDownloadReleasedPolicyGetControlName(t *testing.T) {
	t.Parallel()
	newPolicy := func(controls []reporthandling.Control) *DownloadReleasedPolicy {
		p := NewDownloadReleasedPolicy()
		p.gs = &gitregostore.GitRegoStore{Controls: controls}
		return p
	}

	tests := []struct{ name, id, want string }{
		{"name", "Privileged container", "C-0057"},
		{"name, other case and whitespace", " hostpath MOUNT ", "C-0048"},
		{"control id still works", "c-0057", "C-0057"},
		{"section id still works", "cis-5.2.1", "C-0017"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl, err := newPolicy(nameTestControls()).GetControl(tt.id)
			require.NoError(t, err)
			require.Equal(t, tt.want, ctrl.ControlID)
		})
	}

	t.Run("unknown name is reported as not found", func(t *testing.T) {
		t.Parallel()
		_, err := newPolicy(nameTestControls()).GetControl("no such control")
		require.ErrorIs(t, err, ErrControlNotFound)
		require.ErrorContains(t, err, "not found")
	})
	t.Run("a name shared by two different controls is refused", func(t *testing.T) {
		t.Parallel()
		_, err := newPolicy([]reporthandling.Control{
			{PortalBase: portalBase("Same name"), ControlID: "C-0101"},
			{PortalBase: portalBase("same name"), ControlID: "C-0102"},
		}).GetControl("same name")
		require.ErrorIs(t, err, ErrControlAmbiguous)
	})
}
