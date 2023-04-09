package core

import (
	"context"
	"reflect"
	"testing"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/pkg/hostsensorutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
			got := getUIPrinter(tt.args.ctx, tt.args.verboseMode, tt.args.formatVersion, tt.args.printAttack, tt.args.viewType)

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
