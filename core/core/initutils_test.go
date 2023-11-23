package core

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/cautils/getter"
	"github.com/kubescape/kubescape/v3/core/pkg/hostsensorutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type TenantConfigMock struct {
	clusterName    string
	accountID      string
	accessKey      string
	cloudReportURL string
}

func (tcm *TenantConfigMock) UpdateCachedConfig() error {
	return nil
}
func (tcm *TenantConfigMock) DeleteCachedConfig(ctx context.Context) error {
	return nil
}
func (tcm *TenantConfigMock) GetContextName() string {
	return tcm.clusterName
}
func (tcm *TenantConfigMock) GetAccountID() string {
	return tcm.accountID
}
func (tcm *TenantConfigMock) IsStorageEnabled() bool {
	return true
}
func (tcm *TenantConfigMock) GetConfigObj() *cautils.ConfigObj {
	return &cautils.ConfigObj{
		AccountID:   tcm.accountID,
		ClusterName: tcm.clusterName,
	}
}
func (tcm *TenantConfigMock) GetCloudReportURL() string {
	return tcm.cloudReportURL
}
func (tcm *TenantConfigMock) GetCloudAPIURL() string {
	return ""
}

func (tcm *TenantConfigMock) GenerateAccountID() (string, error) {
	//tcm.accountID = "6a1ff233-5297-4193-bb51-5d67bc841cbf"
	return tcm.accountID, nil
}

func (tcm *TenantConfigMock) DeleteCredentials() error {
	tcm.accountID = ""
	tcm.accessKey = ""
	return nil
}

func (tcm *TenantConfigMock) GetAccessKey() string {
	return tcm.accessKey
}

func TestGetExceptionsGetter(t *testing.T) {
	type args struct {
		ctx                    context.Context
		useExceptions          string
		accountID              string
		downloadReleasedPolicy *getter.DownloadReleasedPolicy
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Test GetExceptionsGetter all empty",
			args: args{
				ctx:                    context.TODO(),
				useExceptions:          "",
				accountID:              "",
				downloadReleasedPolicy: nil,
			},
			want: "*getter.DownloadReleasedPolicy",
		},
		{
			name: "Test GetExceptionsGetter empty useExceptions",
			args: args{
				ctx:                    context.TODO(),
				useExceptions:          "",
				accountID:              "",
				downloadReleasedPolicy: getter.NewDownloadReleasedPolicy(),
			},
			want: "*getter.DownloadReleasedPolicy",
		},
		{
			name: "Test GetExceptionsGetter with useExceptions and empty accountID",
			args: args{
				ctx:                    context.TODO(),
				useExceptions:          "true",
				accountID:              "",
				downloadReleasedPolicy: getter.NewDownloadReleasedPolicy(),
			},
			want: "*getter.LoadPolicy",
		},
		{
			name: "Test GetExceptionsGetter with useExceptions and filled accountID",
			args: args{
				ctx:                    context.TODO(),
				useExceptions:          "true",
				accountID:              "123456789012",
				downloadReleasedPolicy: getter.NewDownloadReleasedPolicy(),
			},
			want: "*getter.LoadPolicy",
		},
		{
			name: "Test GetExceptionsGetter with accountID",
			args: args{
				ctx:                    context.TODO(),
				useExceptions:          "",
				accountID:              "123456789012",
				downloadReleasedPolicy: getter.NewDownloadReleasedPolicy(),
			},
			want: "*v1.KSCloudAPI",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getExceptionsGetter(tt.args.ctx, tt.args.useExceptions, tt.args.accountID, tt.args.downloadReleasedPolicy)
			assert.Equal(t, tt.want, reflect.TypeOf(got).String())
		})
	}
}

func TestPolicyIdentifierIdentities(t *testing.T) {
	type args struct {
		pi []cautils.PolicyIdentifier
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Test PolicyIdentifierIdentities",
			args: args{
				pi: []cautils.PolicyIdentifier{
					{Identifier: "policy1"},
					{Identifier: "policy2"},
					{Identifier: "policy3"},
				},
			},
			want: "policy1,policy2,policy3",
		},
		{
			name: "Test PolicyIdentifierIdentities Empty",
			args: args{
				pi: []cautils.PolicyIdentifier{},
			},
			want: "all",
		},
		{
			name: "Test PolicyIdentifierIdentities nil",
			args: args{
				pi: nil,
			},
			want: "all",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := policyIdentifierIdentities(tt.args.pi)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_getUIPrinter(t *testing.T) {
	scanInfo := &cautils.ScanInfo{
		FormatVersion: "v2",
		VerboseMode:   true,
		View:          "control",
	}
	type args struct {
		ctx           context.Context
		formatVersion string
		viewType      cautils.ViewTypes
		verboseMode   bool
		printAttack   bool
		loggerLevel   helpers.Level
	}
	type wantTypes struct {
		structType    string
		formatVersion string
		viewType      cautils.ViewTypes
		verboseMode   bool
	}
	tests := []struct {
		name          string
		args          args
		want          wantTypes
		testAllFields bool
	}{
		{
			name: "Test getUIPrinter PrettyPrinter",
			args: args{
				ctx:           context.TODO(),
				verboseMode:   scanInfo.VerboseMode,
				formatVersion: scanInfo.FormatVersion,
				printAttack:   scanInfo.PrintAttackTree,
				viewType:      cautils.ViewTypes(scanInfo.View),
				loggerLevel:   helpers.InfoLevel,
			},
			want: wantTypes{
				structType:    "*printer.PrettyPrinter",
				formatVersion: scanInfo.FormatVersion,
				verboseMode:   scanInfo.VerboseMode,
				viewType:      cautils.ViewTypes(scanInfo.View),
			},
			testAllFields: true,
		},
		{
			name: "Test getUIPrinter SilentPrinter",
			args: args{
				ctx:           context.TODO(),
				verboseMode:   scanInfo.VerboseMode,
				formatVersion: scanInfo.FormatVersion,
				printAttack:   scanInfo.PrintAttackTree,
				viewType:      cautils.ViewTypes(scanInfo.View),
				loggerLevel:   helpers.WarningLevel,
			},
			want: wantTypes{
				structType:    "*printer.SilentPrinter",
				formatVersion: "",
				verboseMode:   false,
				viewType:      cautils.ViewTypes(""),
			},
			testAllFields: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger.L().SetLevel(tt.args.loggerLevel.String())
			scanInfo := &cautils.ScanInfo{
				FormatVersion:   tt.args.formatVersion,
				VerboseMode:     tt.args.verboseMode,
				PrintAttackTree: tt.args.printAttack,
				View:            string(tt.args.viewType),
			}

			got := GetUIPrinter(tt.args.ctx, scanInfo, "test-cluster")

			assert.Equal(t, tt.want.structType, reflect.TypeOf(got).String())

			if !tt.testAllFields {
				return
			}

			gotValue := reflect.ValueOf(got).Elem()
			gotFormatVersion := gotValue.FieldByName("formatVersion").String()
			gotVerboseMode := gotValue.FieldByName("verboseMode").Bool()
			gotViewType := cautils.ViewTypes(gotValue.FieldByName("viewType").String())

			if gotFormatVersion != tt.want.formatVersion {
				t.Errorf("Got: %s, want: %s", gotFormatVersion, tt.want.formatVersion)
			}

			if gotVerboseMode != tt.want.verboseMode {
				t.Errorf("Got: %t, want: %t", gotVerboseMode, tt.want.verboseMode)
			}

			if gotViewType != tt.want.viewType {
				t.Errorf("Got: %v, want: %v", gotViewType, tt.want.viewType)
			}
		})
	}
}

func TestGetSensorHandler(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	t.Run("should return mock sensor if not k8s interface is provided", func(t *testing.T) {
		t.Parallel()

		scanInfo := &cautils.ScanInfo{}
		var k8s *k8sinterface.KubernetesApi

		sensor := getHostSensorHandler(ctx, scanInfo, k8s)
		require.NotNil(t, sensor)

		_, isMock := sensor.(*hostsensorutils.HostSensorHandlerMock)
		require.True(t, isMock)
	})

	t.Run("should return mock sensor if the sensor is not enabled", func(t *testing.T) {
		t.Parallel()

		scanInfo := &cautils.ScanInfo{}
		k8s := &k8sinterface.KubernetesApi{}

		sensor := getHostSensorHandler(ctx, scanInfo, k8s)
		require.NotNil(t, sensor)

		_, isMock := sensor.(*hostsensorutils.HostSensorHandlerMock)
		require.True(t, isMock)
	})

	t.Run("should return mock sensor if the sensor is disabled", func(t *testing.T) {
		t.Parallel()

		falseFlag := cautils.NewBoolPtr(nil)
		falseFlag.SetBool(false)
		scanInfo := &cautils.ScanInfo{
			HostSensorEnabled: falseFlag,
		}
		k8s := &k8sinterface.KubernetesApi{}

		sensor := getHostSensorHandler(ctx, scanInfo, k8s)
		require.NotNil(t, sensor)

		_, isMock := sensor.(*hostsensorutils.HostSensorHandlerMock)
		require.True(t, isMock)
	})

	t.Run("should return mock sensor if the sensor is enabled, but can't deploy (nil)", func(t *testing.T) {
		t.Parallel()

		falseFlag := cautils.NewBoolPtr(nil)
		falseFlag.SetBool(true)
		scanInfo := &cautils.ScanInfo{
			HostSensorEnabled: falseFlag,
		}
		var k8s *k8sinterface.KubernetesApi

		sensor := getHostSensorHandler(ctx, scanInfo, k8s)
		require.NotNil(t, sensor)

		_, isMock := sensor.(*hostsensorutils.HostSensorHandlerMock)
		require.True(t, isMock)
	})

	// TODO(fredbi): need to share the k8s client mock to test a happy path / deployment failure path
}

func TestSetSubmitBehavior(t *testing.T) {
	type args struct {
		scanInfo                *cautils.ScanInfo
		tenantConfig            *TenantConfigMock
		isScanTypeForSubmission bool
		isLocal                 bool
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Test SetSubmitBehavior !setSubmitBehavior and keep-local",
			args: args{
				scanInfo: &cautils.ScanInfo{
					ScanType: cautils.ScanTypeControl,
					Local:    true,
				},
				tenantConfig: &TenantConfigMock{
					clusterName: "test",
					accountID:   "",
					accessKey:   "",
				},
				isScanTypeForSubmission: false,
				isLocal:                 true,
			},
			want: false,
		},
		{
			name: "Test SetSubmitBehavior !setSubmitBehavior and !keep-local",
			args: args{
				scanInfo: &cautils.ScanInfo{
					ScanType: cautils.ScanTypeControl,
					Local:    false,
				},
				tenantConfig: &TenantConfigMock{
					clusterName: "test",
					accountID:   "",
					accessKey:   "",
				},
				isScanTypeForSubmission: false,
				isLocal:                 false,
			},
			want: false,
		},
		{
			name: "Test SetSubmitBehavior setSubmitBehavior and keep-local",
			args: args{
				scanInfo: &cautils.ScanInfo{
					ScanType: cautils.ScanTypeCluster,
					Local:    true,
				},
				tenantConfig: &TenantConfigMock{
					clusterName: "test",
					accountID:   "",
					accessKey:   "",
				},
				isScanTypeForSubmission: true,
				isLocal:                 true,
			},
			want: false,
		},
		{
			name: "Test SetSubmitBehavior !keep-local and setSubmitBehavior",
			args: args{
				scanInfo: &cautils.ScanInfo{
					ScanType: cautils.ScanTypeCluster,
					Local:    false,
				},
				tenantConfig: &TenantConfigMock{
					clusterName: "test",
					accountID:   "",
					accessKey:   "",
				},
				isScanTypeForSubmission: true,
				isLocal:                 false,
			},
			want: false,
		}, // TODO: Add test "If CloudReportURL is set"
		{
			name: "Test SetSubmitBehavior CloudReportURL is set, no AccountID",
			args: args{
				scanInfo: &cautils.ScanInfo{
					ScanType: cautils.ScanTypeCluster,
					Local:    false,
				},
				tenantConfig: &TenantConfigMock{
					clusterName:    "test",
					accountID:      "",
					accessKey:      "",
					cloudReportURL: "https://example.kubescape.com",
				},
				isScanTypeForSubmission: true,
				isLocal:                 false,
			},
			want: true,
		},
		{
			name: "Test SetSubmitBehavior CloudReportURL is set, Invalid AccountID",
			args: args{
				scanInfo: &cautils.ScanInfo{
					ScanType: cautils.ScanTypeCluster,
					Local:    false,
				},
				tenantConfig: &TenantConfigMock{
					clusterName:    "test",
					accountID:      "123456789012",
					accessKey:      "",
					cloudReportURL: "https://example.kubescape.com",
				},
				isScanTypeForSubmission: true,
				isLocal:                 false,
			},
			want: false,
		},
		{
			name: "Test SetSubmitBehavior CloudReportURL is set, Valid AccountID",
			args: args{
				scanInfo: &cautils.ScanInfo{
					ScanType: cautils.ScanTypeCluster,
					Local:    false,
				},
				tenantConfig: &TenantConfigMock{
					clusterName:    "test",
					accountID:      "6a1ff233-5297-4193-bb51-5d67bc841cbf",
					accessKey:      "",
					cloudReportURL: "https://example.kubescape.com",
				},
				isScanTypeForSubmission: true,
				isLocal:                 false,
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.args.isScanTypeForSubmission, isScanTypeForSubmission(tt.args.scanInfo.ScanType))
			require.Equal(t, tt.args.isLocal, tt.args.scanInfo.Local)

			setSubmitBehavior(tt.args.scanInfo, tt.args.tenantConfig)

			assert.Equal(t, tt.want, tt.args.scanInfo.Submit)
		})
	}
}

func TestIsScanTypeForSubmission(t *testing.T) {
	test := []struct {
		name     string
		scanType cautils.ScanTypes
		want     bool
	}{
		{
			name:     "cluster scan",
			scanType: cautils.ScanTypeCluster,
			want:     true,
		},
		{
			name:     "repo scan",
			scanType: cautils.ScanTypeRepo,
			want:     true,
		},
		{
			name:     "workload scan",
			scanType: cautils.ScanTypeWorkload,
			want:     false,
		},
		{
			name:     "control scan",
			scanType: cautils.ScanTypeControl,
			want:     false,
		},
		{
			name:     "framework scan",
			scanType: cautils.ScanTypeFramework,
			want:     true,
		},
		{
			name:     "image scan",
			scanType: cautils.ScanTypeImage,
			want:     true,
		},
	}

	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			got := isScanTypeForSubmission(tt.scanType)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetDefaultFrameworksPaths(t *testing.T) {
	result := getDefaultFrameworksPaths()

	assert.NotEmpty(t, result)
	for _, path := range result {
		assert.NotEmpty(t, path)
		assert.True(t, strings.HasSuffix(path, ".json"))
	}
}

// getDownloadReleasedPolicy should always have a non-nil result
func TestGetDownloadReleasedPolicy(t *testing.T) {
	ctx := context.Background()
	downloadReleasedPolicy := getter.NewDownloadReleasedPolicy()

	require.NoError(t, downloadReleasedPolicy.SetRegoObjects())

	result := getDownloadReleasedPolicy(ctx, downloadReleasedPolicy)

	assert.NotNil(t, result)
}
