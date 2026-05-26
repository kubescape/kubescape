package getter

import (
	"fmt"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type exceptionsGetterStub struct {
	exceptions []armotypes.PostureExceptionPolicy
	err        error
}

func (s *exceptionsGetterStub) GetExceptions(_ string) ([]armotypes.PostureExceptionPolicy, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.exceptions, nil
}

func TestMergedExceptionsGetter(t *testing.T) {
	tests := []struct {
		name    string
		getter  *MergedExceptionsGetter
		wantLen int
		wantErr bool
	}{
		{
			name:    "nil getter returns empty",
			getter:  nil,
			wantLen: 0,
		},
		{
			name: "primary only",
			getter: NewMergedExceptionsGetter(
				&exceptionsGetterStub{exceptions: []armotypes.PostureExceptionPolicy{{PolicyType: "base"}}},
				nil,
			),
			wantLen: 1,
		},
		{
			name: "merge both",
			getter: NewMergedExceptionsGetter(
				&exceptionsGetterStub{exceptions: []armotypes.PostureExceptionPolicy{{PolicyType: "base"}}},
				&exceptionsGetterStub{exceptions: []armotypes.PostureExceptionPolicy{{PolicyType: "crd"}}},
			),
			wantLen: 2,
		},
		{
			name: "secondary error ignored",
			getter: NewMergedExceptionsGetter(
				&exceptionsGetterStub{exceptions: []armotypes.PostureExceptionPolicy{{PolicyType: "base"}}},
				&exceptionsGetterStub{err: fmt.Errorf("secondary failed")},
			),
			wantLen: 1,
		},
		{
			name: "primary error returned",
			getter: NewMergedExceptionsGetter(
				&exceptionsGetterStub{err: fmt.Errorf("primary failed")},
				&exceptionsGetterStub{exceptions: []armotypes.PostureExceptionPolicy{{PolicyType: "crd"}}},
			),
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, err := tc.getter.GetExceptions("cluster-a")
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Len(t, out, tc.wantLen)
		})
	}
}
