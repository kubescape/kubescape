package policyhandler

import (
	"context"
	"fmt"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/mocks"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
)

const (
	FrameworkName = "framework-0006-0013"
)

var (
	CachedControlInputs = map[string][]string{
		"control1": {"input1", "input2"},
		"control2": {"input3", "input4"},
	}
	CachedExceptions = []armotypes.PostureExceptionPolicy{*mocks.MockExceptionAllKinds(&armotypes.PosturePolicy{FrameworkName: "nsa"})}
)

type ExceptionsGetterMock struct{}
type ControlsInputsGetterMock struct{}
type PolicyGetterMock struct{}

func (mock *ExceptionsGetterMock) GetExceptions(clusterName string) ([]armotypes.PostureExceptionPolicy, error) {
	return CachedExceptions, nil
}
func (mock *ControlsInputsGetterMock) GetControlsInputs(clusterName string) (map[string][]string, error) {
	return CachedControlInputs, nil
}
func (mock *PolicyGetterMock) GetControl(name string) (*reporthandling.Control, error) {
	return &reporthandling.Control{}, nil
}
func (mock *PolicyGetterMock) GetFramework(name string) (*reporthandling.Framework, error) {
	return mocks.MockFramework_0006_0013(), nil
}
func (mock *PolicyGetterMock) GetFrameworks() ([]reporthandling.Framework, error) {
	return []reporthandling.Framework{}, nil
}
func (mock *PolicyGetterMock) ListControls() ([]string, error) {
	return []string{}, nil
}
func (mock *PolicyGetterMock) ListFrameworks() ([]string, error) {
	return []string{}, nil
}

// Returns a PolicyHandler instance with the given clusterName.
func TestNewPolicyHandler_ClusterNameNotEmpty(t *testing.T) {
	clusterName := "test-cluster"
	policyHandler := NewPolicyHandler(clusterName)
	assert.NotNil(t, policyHandler)
	assert.Equal(t, clusterName, policyHandler.clusterName)
}

// Returns the same PolicyHandler instance if called multiple times.
func TestNewPolicyHandler_MultiplePoliciesWithSameClusterName(t *testing.T) {
	clusterName := "test-cluster"
	policyHandler1 := NewPolicyHandler(clusterName)
	policyHandler2 := NewPolicyHandler(clusterName)
	assert.Equal(t, policyHandler1, policyHandler2)
}

func TestCollectPolicies(t *testing.T) {
	testCases := []struct {
		name          string
		policyHandler *PolicyHandler
		policyIdent   []cautils.PolicyIdentifier
		scanInfo      *cautils.ScanInfo
		expectedError error
	}{
		{
			name:          "Unknown policy",
			policyHandler: NewPolicyHandler("test-cluster"),
			policyIdent:   []cautils.PolicyIdentifier{{Identifier: "NotExistingPolicy"}},
			scanInfo:      &cautils.ScanInfo{},
			expectedError: fmt.Errorf("unknown policy kind"),
		},
		{
			name:          "Collect Framework policy",
			policyHandler: NewPolicyHandler("test-cluster"),
			policyIdent:   []cautils.PolicyIdentifier{{Identifier: FrameworkName, Kind: "Framework"}},
			scanInfo: &cautils.ScanInfo{
				Getters: cautils.Getters{
					PolicyGetter:         &PolicyGetterMock{},
					ExceptionsGetter:     &ExceptionsGetterMock{},
					ControlsInputsGetter: &ControlsInputsGetterMock{},
				},
			},
			expectedError: nil,
		},
		{
			name:          "Collect Control policy",
			policyHandler: NewPolicyHandler("test-cluster"),
			policyIdent:   []cautils.PolicyIdentifier{{Identifier: "", Kind: "Control"}},
			scanInfo: &cautils.ScanInfo{
				Getters: cautils.Getters{
					PolicyGetter:         &PolicyGetterMock{},
					ExceptionsGetter:     &ExceptionsGetterMock{},
					ControlsInputsGetter: &ControlsInputsGetterMock{},
				},
			},
			expectedError: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.TODO()
			tc.policyHandler.getters = &cautils.Getters{
				PolicyGetter:         &PolicyGetterMock{},
				ExceptionsGetter:     &ExceptionsGetterMock{},
				ControlsInputsGetter: &ControlsInputsGetterMock{},
			}

			opaSessionObj, err := tc.policyHandler.CollectPolicies(ctx, tc.policyIdent, tc.scanInfo)

			assert.Equal(t, tc.expectedError, err)
			assert.NotNil(t, opaSessionObj)
		})
	}
}

// Should return a deep copy of the input slice of reporthandling.Framework structs
func TestDeepCopyPolicies_ShouldReturnDeepCopyOfInputSlice(t *testing.T) {
	src := []reporthandling.Framework{
		{
			Controls: []reporthandling.Control{
				{
					ControlID: "c-0001",
				},
			},
		},
		{
			Controls: []reporthandling.Control{},
		},
	}

	// Act
	dst, err := deepCopyPolicies(src)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, dst)
}

func TestDownloadScanPolicies(t *testing.T) {
	testCases := []struct {
		name           string
		policyHandler  *PolicyHandler
		policyIdent    []cautils.PolicyIdentifier
		scanInfo       *cautils.ScanInfo
		expectedError  error
		expectedResult []reporthandling.Framework
	}{
		{
			name:           "Unknown kind",
			policyHandler:  NewPolicyHandler("test-cluster"),
			policyIdent:    []cautils.PolicyIdentifier{{Identifier: "framework-0006-0013", Kind: "NotExistingKind"}},
			scanInfo:       &cautils.ScanInfo{},
			expectedError:  fmt.Errorf("unknown policy kind"),
			expectedResult: []reporthandling.Framework{},
		},
		{
			name:          "Kind Framework",
			policyHandler: NewPolicyHandler("test-cluster"),
			policyIdent:   []cautils.PolicyIdentifier{{Identifier: "framework-0006-0013", Kind: "Framework"}},
			scanInfo:      &cautils.ScanInfo{},
			expectedError: nil,
			expectedResult: []reporthandling.Framework{
				*mocks.MockFramework_0006_0013(),
			},
		},
		{
			name:          "Kind Control",
			policyHandler: NewPolicyHandler("test-cluster"),
			policyIdent:   []cautils.PolicyIdentifier{{Identifier: "control1", Kind: "Control"}},
			scanInfo:      &cautils.ScanInfo{},
			expectedError: nil,
			expectedResult: []reporthandling.Framework{
				{
					Controls: []reporthandling.Control{
						{
							ControlID: "",
						},
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.TODO()
			tc.policyHandler.getters = &cautils.Getters{
				PolicyGetter:         &PolicyGetterMock{},
				ExceptionsGetter:     &ExceptionsGetterMock{},
				ControlsInputsGetter: &ControlsInputsGetterMock{},
			}

			frameworks, err := tc.policyHandler.downloadScanPolicies(ctx, tc.policyIdent)

			assert.Equal(t, tc.expectedError, err)
			assert.Equal(t, tc.expectedResult, frameworks)
		})
	}
}

func TestGetExceptions(t *testing.T) {
	cachedExceptions := CachedExceptions
	policyHandler := NewPolicyHandler("test-cluster")
	policyHandler.getters = &cautils.Getters{
		ExceptionsGetter: &ExceptionsGetterMock{},
	}
	exceptions, err := policyHandler.getExceptions()

	assert.NoError(t, err)
	assert.Equal(t, cachedExceptions, exceptions)
}

func TestGetControlInputs(t *testing.T) {
	cachedControlInputs := CachedControlInputs
	policyHandler := NewPolicyHandler("test-cluster")
	policyHandler.getters = &cautils.Getters{
		ControlsInputsGetter: &ControlsInputsGetterMock{},
	}

	controlInputs, err := policyHandler.getControlInputs()

	assert.NoError(t, err)
	assert.Equal(t, cachedControlInputs, controlInputs)
}
