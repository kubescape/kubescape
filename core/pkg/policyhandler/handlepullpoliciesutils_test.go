package policyhandler

import (
	"testing"

	"github.com/kubescape/opa-utils/reporthandling"
)

func Test_validateFramework(t *testing.T) {
	type args struct {
		framework *reporthandling.Framework
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "empty framework",
			args: args{
				framework: &reporthandling.Framework{
					Controls: []reporthandling.Control{},
				},
			},
			wantErr: true,
		},
		{
			name: "none empty framework",
			args: args{
				framework: &reporthandling.Framework{
					Controls: []reporthandling.Control{
						{
							ControlID: "c-0001",
						},
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateFramework(tt.args.framework); (err != nil) != tt.wantErr {
				t.Errorf("validateControls() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
