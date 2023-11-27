package cautils

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"golang.org/x/mod/semver"
)

func TestGetKubernetesObjects(t *testing.T) {
}

var rule_v1_0_131 = &reporthandling.PolicyRule{PortalBase: armotypes.PortalBase{
	Attributes: map[string]interface{}{"useUntilKubescapeVersion": "v1.0.132"}}}
var rule_v1_0_132 = &reporthandling.PolicyRule{PortalBase: armotypes.PortalBase{
	Attributes: map[string]interface{}{"useFromKubescapeVersion": "v1.0.132", "useUntilKubescapeVersion": "v1.0.133"}}}
var rule_v1_0_133 = &reporthandling.PolicyRule{PortalBase: armotypes.PortalBase{
	Attributes: map[string]interface{}{"useFromKubescapeVersion": "v1.0.133", "useUntilKubescapeVersion": "v1.0.134"}}}
var rule_v1_0_134 = &reporthandling.PolicyRule{PortalBase: armotypes.PortalBase{
	Attributes: map[string]interface{}{"useFromKubescapeVersion": "v1.0.134"}}}
var rule_invalid_from = &reporthandling.PolicyRule{PortalBase: armotypes.PortalBase{
	Attributes: map[string]interface{}{"useFromKubescapeVersion": 1.0135, "useUntilKubescapeVersion": "v1.0.135"}}}
var rule_invalid_until = &reporthandling.PolicyRule{PortalBase: armotypes.PortalBase{
	Attributes: map[string]interface{}{"useFromKubescapeVersion": "v1.0.135", "useUntilKubescapeVersion": 1.0135}}}

func TestIsRuleKubescapeVersionCompatible(t *testing.T) {
	// local build- no build number

	// should not crash when the value of useUntilKubescapeVersion is not a string
	buildNumberMock := "v1.0.135"
	assert.False(t, isRuleKubescapeVersionCompatible(rule_invalid_from.Attributes, buildNumberMock))
	assert.False(t, isRuleKubescapeVersionCompatible(rule_invalid_until.Attributes, buildNumberMock))
	// should use only rules that don't have "until"
	buildNumberMock = ""
	assert.False(t, isRuleKubescapeVersionCompatible(rule_v1_0_131.Attributes, buildNumberMock))
	assert.False(t, isRuleKubescapeVersionCompatible(rule_v1_0_132.Attributes, buildNumberMock))
	assert.False(t, isRuleKubescapeVersionCompatible(rule_v1_0_133.Attributes, buildNumberMock))
	assert.True(t, isRuleKubescapeVersionCompatible(rule_v1_0_134.Attributes, buildNumberMock))

	// should only use rules that version is in range of use
	buildNumberMock = "v1.0.130"
	assert.True(t, isRuleKubescapeVersionCompatible(rule_v1_0_131.Attributes, buildNumberMock))
	assert.False(t, isRuleKubescapeVersionCompatible(rule_v1_0_132.Attributes, buildNumberMock))
	assert.False(t, isRuleKubescapeVersionCompatible(rule_v1_0_133.Attributes, buildNumberMock))
	assert.False(t, isRuleKubescapeVersionCompatible(rule_v1_0_134.Attributes, buildNumberMock))

	// should only use rules that version is in range of use
	buildNumberMock = "v1.0.132"
	assert.False(t, isRuleKubescapeVersionCompatible(rule_v1_0_131.Attributes, buildNumberMock))
	assert.True(t, isRuleKubescapeVersionCompatible(rule_v1_0_132.Attributes, buildNumberMock))
	assert.False(t, isRuleKubescapeVersionCompatible(rule_v1_0_133.Attributes, buildNumberMock))
	assert.False(t, isRuleKubescapeVersionCompatible(rule_v1_0_134.Attributes, buildNumberMock))

	// should only use rules that version is in range of use
	buildNumberMock = "v1.0.133"
	assert.False(t, isRuleKubescapeVersionCompatible(rule_v1_0_131.Attributes, buildNumberMock))
	assert.False(t, isRuleKubescapeVersionCompatible(rule_v1_0_132.Attributes, buildNumberMock))
	assert.True(t, isRuleKubescapeVersionCompatible(rule_v1_0_133.Attributes, buildNumberMock))
	assert.False(t, isRuleKubescapeVersionCompatible(rule_v1_0_134.Attributes, buildNumberMock))

	// should only use rules that version is in range of use
	buildNumberMock = "v1.0.135"
	assert.False(t, isRuleKubescapeVersionCompatible(rule_v1_0_131.Attributes, buildNumberMock))
	assert.False(t, isRuleKubescapeVersionCompatible(rule_v1_0_132.Attributes, buildNumberMock))
	assert.False(t, isRuleKubescapeVersionCompatible(rule_v1_0_133.Attributes, buildNumberMock))
	assert.True(t, isRuleKubescapeVersionCompatible(rule_v1_0_134.Attributes, buildNumberMock))
}

func TestCheckLatestVersion_Semver_Compare(t *testing.T) {
	assert.Equal(t, -1, semver.Compare("v2.0.150", "v2.0.151"))
	assert.Equal(t, 0, semver.Compare("v2.0.150", "v2.0.150"))
	assert.Equal(t, 1, semver.Compare("v2.0.150", "v2.0.149"))
	assert.Equal(t, -1, semver.Compare("v2.0.150", "v3.0.150"))

}

func TestCheckLatestVersion(t *testing.T) {
	type args struct {
		ctx         context.Context
		versionData *VersionCheckRequest
		versionURL  string
	}
	tests := []struct {
		name string
		args args
		err  error
	}{
		{
			name: "Get latest version",
			args: args{
				ctx:         context.Background(),
				versionData: &VersionCheckRequest{},
				versionURL:  "https://us-central1-elated-pottery-310110.cloudfunctions.net/ksgf1v1",
			},
			err: nil,
		},
		{
			name: "Failed to get latest version",
			args: args{
				ctx:         context.Background(),
				versionData: &VersionCheckRequest{},
				versionURL:  "https://example.com",
			},
			err: fmt.Errorf("failed to get latest version"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &VersionCheckHandler{
				versionURL: tt.args.versionURL,
			}
			err := v.CheckLatestVersion(tt.args.ctx, tt.args.versionData)

			assert.Equal(t, tt.err, err)
		})
	}
}

func TestVersionCheckHandler_getLatestVersion(t *testing.T) {
	type fields struct {
		versionURL string
	}
	type args struct {
		versionData *VersionCheckRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *VersionCheckResponse
		wantErr bool
	}{
		{
			name: "Get latest version",
			fields: fields{
				versionURL: "https://us-central1-elated-pottery-310110.cloudfunctions.net/ksgf1v1",
			},
			args: args{
				versionData: &VersionCheckRequest{
					Client: "kubescape",
				},
			},
			want: &VersionCheckResponse{
				Client:       "kubescape",
				ClientUpdate: "v3.0.0",
			},
			wantErr: false,
		},
		{
			name: "Failed to get latest version",
			fields: fields{
				versionURL: "https://example.com",
			},
			args: args{
				versionData: &VersionCheckRequest{},
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &VersionCheckHandler{
				versionURL: tt.fields.versionURL,
			}
			got, err := v.getLatestVersion(tt.args.versionData)
			if (err != nil) != tt.wantErr {
				t.Errorf("VersionCheckHandler.getLatestVersion() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("VersionCheckHandler.getLatestVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetTriggerSource(t *testing.T) {
	// Running in github actions pipeline
	os.Setenv("GITHUB_ACTIONS", "true")
	source := getTriggerSource()
	assert.Equal(t, "pipeline", source)

	os.Args[0] = "ksserver"
	source = getTriggerSource()
	assert.Equal(t, "microservice", source)
}
