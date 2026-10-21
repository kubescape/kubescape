package policyhandler

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/require"
)

// countingControlGetter wraps a getter and records every identifier asked for.
type countingControlGetter struct {
	getter.IPolicyGetter
	asked []string
	err   error
}

func (c *countingControlGetter) GetControl(id string) (*reporthandling.Control, error) {
	c.asked = append(c.asked, id)
	if c.err != nil {
		return nil, c.err
	}
	return c.IPolicyGetter.GetControl(id)
}

// A control that does not exist keeps the message scan users already see and
// stays recognizable as an unknown control to callers further up.
func TestControlDownloadErrorKeepsErrorIdentity(t *testing.T) {
	// The released-policy getter's message is rewritten for the user; the
	// original error stays reachable.
	rewritten := controlDownloadError(fmt.Errorf("control 'c-0005' not found: %w", getter.ErrControlNotFound), "c-0005")
	require.ErrorIs(t, rewritten, getter.ErrControlNotFound)
	require.EqualError(t, rewritten, "control 'c-0005' not found, run `kubescape list controls` for available controls")

	_, err := downloadedControlIDs(t, controlPolicyGetter(t, sectionFramework), "CIS-9.9.9")
	require.ErrorIs(t, err, getter.ErrControlNotFound)
	require.ErrorIs(t, err, getter.ErrControlNotMatching)
	require.EqualError(t, err, "controlID: CIS-9.9.9: control from file not matching")
}

// Only an error carrying the unknown-control sentinel is rewritten; text alone
// never is.
func TestControlDownloadErrorRewritesOnlyTheSentinel(t *testing.T) {
	plain := errors.New("control 'c-0005' not found")
	require.Same(t, plain, controlDownloadError(plain, "c-0005"))
}

func TestControlDownloadErrorAmbiguousKeepsCandidates(t *testing.T) {
	lp := controlPolicyGetter(t, `{"name":"x","controls":[
 {"controlID":"C-0001","id":"X-1"},{"controlID":"C-0002","id":"X-1"}]}`)
	_, err := downloadedControlIDs(t, lp, "x-1")

	var ambiguous *getter.AmbiguousControlError
	require.ErrorAs(t, err, &ambiguous)
	require.Equal(t, []string{"C-0001", "C-0002"}, ambiguous.Matches)
	require.NotErrorIs(t, err, getter.ErrControlNotFound)
}

// A catalog failure must not read as an unknown control, even when its text
// says "not found": the caller would then blame the user's selection.
func TestControlDownloadErrorCatalogFailureIsNotAnUnknownControl(t *testing.T) {
	boom := errors.New("policy catalog: file not found")
	g := &countingControlGetter{IPolicyGetter: controlPolicyGetter(t, sectionFramework), err: boom}

	_, err := NewPolicyHandler("control-error-test").downloadScanPolicies(
		context.Background(), controlIdentifiers("C-0286"), &cautils.Getters{PolicyGetter: g})
	require.ErrorIs(t, err, boom)
	require.NotErrorIs(t, err, getter.ErrControlNotFound)
}

// The scan stops at the first control it cannot resolve; identifiers after it
// are not looked up.
func TestDownloadScanPoliciesStopsAtFirstUnresolvedControl(t *testing.T) {
	g := &countingControlGetter{IPolicyGetter: controlPolicyGetter(t, sectionFramework)}

	_, err := NewPolicyHandler("control-failfast-test").downloadScanPolicies(
		context.Background(), controlIdentifiers("C-0286", "C-9999", "C-0012"), &cautils.Getters{PolicyGetter: g})
	require.ErrorIs(t, err, getter.ErrControlNotFound)
	require.Equal(t, []string{"C-0286", "C-9999"}, g.asked)
}
