package core

import (
	"context"
	"reflect"
	"testing"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/stretchr/testify/assert"
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
