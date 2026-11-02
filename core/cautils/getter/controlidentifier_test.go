package getter

import (
	"testing"

	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeControlIdentifier(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		id   string
		want string
	}{
		{name: "already lowercase", id: "c-0286", want: "c-0286"},
		{name: "uppercase is lowercased", id: "C-0286", want: "c-0286"},
		{name: "mixed case", id: "C-0286", want: "c-0286"},
		{name: "leading whitespace trimmed", id: "  C-0286", want: "c-0286"},
		{name: "trailing whitespace trimmed", id: "C-0286  ", want: "c-0286"},
		{name: "both sides trimmed", id: "  C-0286  ", want: "c-0286"},
		{name: "tabs trimmed", id: "\tC-0286\t", want: "c-0286"},
		{name: "section number", id: " CIS-3.1.1 ", want: "cis-3.1.1"},
		{name: "empty string", id: "", want: ""},
		{name: "whitespace only", id: "   ", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, normalizeControlIdentifier(tt.id))
		})
	}
}

func TestNewControlMatcher(t *testing.T) {
	t.Parallel()

	m := newControlMatcher("C-0286")
	require.NotNil(t, m)
	assert.Equal(t, "c-0286", m.id)

	m = newControlMatcher("  C-0286 ")
	require.Equal(t, "c-0286", m.id)

	m = newControlMatcher("CIS-3.1.1")
	require.Equal(t, "cis-3.1.1", m.id)
}

func TestControlMatcherOffer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		id      string
		control reporthandling.Control
		want    bool // true when offer returns true (ControlID matches identifier)
	}{
		{name: "exact ControlID match", id: "c-0286", control: reporthandling.Control{ControlID: "C-0286"}, want: true},
		{name: "case-insensitive ControlID match", id: "C-0286", control: reporthandling.Control{ControlID: "c-0286"}, want: true},
		{name: "ControlID mismatch", id: "c-0286", control: reporthandling.Control{ControlID: "C-0287"}, want: false},
		{name: "Control_ID section match", id: "cis-3.1.1", control: reporthandling.Control{ControlID: "C-0286", Control_ID: "CIS-3.1.1"}, want: false},
		{name: "Control_ID case-insensitive match", id: "CIS-3.1.1", control: reporthandling.Control{ControlID: "C-0286", Control_ID: "cis-3.1.1"}, want: false},
		{name: "Control_ID mismatch", id: "cis-3.1.1", control: reporthandling.Control{ControlID: "C-0286", Control_ID: "CIS-3.1.2"}, want: false},
		{name: "whitespace trimmed in identifier", id: "  c-0286  ", control: reporthandling.Control{ControlID: "C-0286"}, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := newControlMatcher(tt.id)
			got := m.offer(&tt.control)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestControlMatcherOfferAccumulatesDistinctSections(t *testing.T) {
	t.Parallel()

	m := newControlMatcher("cis-3.1.1")

	// First control with this section is recorded
	c1 := reporthandling.Control{ControlID: "C-0286", Control_ID: "CIS-3.1.1"}
	assert.False(t, m.offer(&c1))

	// Same control again (by section) is rejected as already recorded
	c1dup := reporthandling.Control{ControlID: "C-0286", Control_ID: "CIS-3.1.1"}
	assert.False(t, m.offer(&c1dup))

	// A control whose ControlID matches the identifier returns true
	cidMatch := reporthandling.Control{ControlID: "CIS-3.1.1"}
	assert.True(t, m.offer(&cidMatch))
}

func TestControlMatcherBySection(t *testing.T) {
	t.Parallel()

	t.Run("no candidates returns nil nil", func(t *testing.T) {
		t.Parallel()
		m := newControlMatcher("cis-9.9.9")
		control, err := m.bySection()
		assert.Nil(t, control)
		assert.NoError(t, err)
	})

	t.Run("single candidate returns the control", func(t *testing.T) {
		t.Parallel()
		m := newControlMatcher("cis-3.1.1")
		m.offer(&reporthandling.Control{ControlID: "C-0286", Control_ID: "CIS-3.1.1"})

		control, err := m.bySection()
		require.NoError(t, err)
		require.NotNil(t, control)
		assert.Equal(t, "C-0286", control.ControlID)
		assert.Equal(t, "CIS-3.1.1", control.Control_ID)
	})

	t.Run("multiple distinct controls return ambiguous error", func(t *testing.T) {
		t.Parallel()
		m := newControlMatcher("x-1")
		m.offer(&reporthandling.Control{ControlID: "C-0001", Control_ID: "X-1"})
		m.offer(&reporthandling.Control{ControlID: "C-0002", Control_ID: "X-1"})

		control, err := m.bySection()
		assert.Nil(t, control)
		require.Error(t, err)

		var ambiguous *AmbiguousControlError
		require.ErrorAs(t, err, &ambiguous)
		require.ErrorIs(t, err, ErrControlAmbiguous)
		assert.Equal(t, "x-1", ambiguous.Identifier)
		assert.Equal(t, []string{"C-0001", "C-0002"}, ambiguous.Matches)
		assert.Contains(t, err.Error(), "C-0001")
		assert.Contains(t, err.Error(), "C-0002")
	})

	t.Run("same control repeated is not ambiguous", func(t *testing.T) {
		t.Parallel()
		m := newControlMatcher("cis-3.1.1")
		m.offer(&reporthandling.Control{ControlID: "C-0286", Control_ID: "CIS-3.1.1"})
		m.offer(&reporthandling.Control{ControlID: "C-0286", Control_ID: "CIS-3.1.1"})

		control, err := m.bySection()
		require.NoError(t, err)
		require.NotNil(t, control)
		assert.Equal(t, "C-0286", control.ControlID)
	})
}
