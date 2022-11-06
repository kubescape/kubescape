package core

import (
	"os"
	"path/filepath"
	"testing"
)

func onlineBoutiquePath() string {
	o, _ := os.Getwd()
	return filepath.Join(filepath.Dir(o), "..", "examples", "online-boutique")
}

func Test_fixFile(t *testing.T) {
	type args struct {
		filePath string
		fixPath  string
	}
	tests := []struct {
		name string
		args args
		want error
	}{
		{
			name: "test fix file",
			args: args{
				filePath: filepath.Join(onlineBoutiquePath(), "adservice.yaml:0"),
				fixPath:  "spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem=true",
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// fixPathToExpectedLineAndColumn := map[string]Location{
			// 	"spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem=true":        {Line: 31, Column: 9},
			// 	"spec.template.spec.containers[0].securityContext.runAsNonRoot=true":                  {Line: 31, Column: 9},
			// 	"spec.template.spec.containers[0].securityContext.allowPrivilegeEscalation=false":     {Line: 31, Column: 9},
			// 	"spec.template.spec.containers[0].securityContext.capabilities.drop=NET_RAW":          {Line: 31, Column: 9},
			// 	"spec.template.spec.containers[0].securityContext.seLinuxOptions=YOUR_VALUE":          {Line: 31, Column: 9},
			// 	"spec.template.spec.containers[0].securityContext.seccompProfile=YOUR_VALUE":          {Line: 31, Column: 9},
			// 	"spec.template.spec.securityContext.runAsNonRoot=true":                                {Line: 28, Column: 7},
			// 	"spec.template.spec.securityContext.allowPrivilegeEscalation=false":                   {Line: 28, Column: 7},
			// 	"spec.template.spec.containers[0].securityContext.seccompProfile.type=RuntimeDefault": {Line: 31, Column: 9},
			// 	"spec.template.spec.containers[0].image":                                              {Line: 32, Column: 16},
			// 	"spec.template.spec.containers[0].seccompProfile=YOUR_VALUE":                          {Line: 31, Column: 9},
			// 	"spec.template.spec.containers[0].seLinuxOptions=YOUR_VALUE":                          {Line: 31, Column: 9},
			// 	"spec.template.spec.containers[0].capabilities.drop=YOUR_VALUE":                       {Line: 31, Column: 9},
			// 	"metadata.namespace=YOUR_NAMESPACE":                                                   {Line: 18, Column: 3},
			// 	"metadata.labels=YOUR_VALUE":                                                          {Line: 18, Column: 3},
			// 	"spec.template.metadata.labels=YOUR_VALUE":                                            {Line: 26, Column: 9},
			// 	"spec.template.spec.containers[0].resources.limits.cpu=YOUR_VALUE":                    {Line: 49, Column: 18},
			// }

			if got := fixFile(tt.args.filePath, tt.args.fixPath); got != tt.want {
				t.Errorf("fixFile() = %v, want %v", got, tt.want)
			}
		})
	}
}
