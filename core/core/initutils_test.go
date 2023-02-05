package core

import (
	"context"
	"reflect"
	"testing"

	"github.com/kubescape/kubescape/v2/core/cautils"
)

func Test_getUIPrinter(t *testing.T) {
	scanInfo := &cautils.ScanInfo{
		FormatVersion: "v2",
		VerboseMode:   true,
		View:          "control",
	}
	wantFormatVersion := scanInfo.FormatVersion
	wantVerboseMode := scanInfo.VerboseMode
	wantViewType := cautils.ViewTypes(scanInfo.View)

	got := getUIPrinter(context.TODO(), scanInfo.VerboseMode, scanInfo.FormatVersion, scanInfo.PrintAttackTree, cautils.ViewTypes(scanInfo.View))

	gotValue := reflect.ValueOf(got).Elem()
	gotFormatVersion := gotValue.FieldByName("formatVersion").String()
	gotVerboseMode := gotValue.FieldByName("verboseMode").Bool()
	gotViewType := cautils.ViewTypes(gotValue.FieldByName("viewType").String())

	if gotFormatVersion != wantFormatVersion {
		t.Errorf("Got: %s, want: %s", gotFormatVersion, wantFormatVersion)
	}

	if gotVerboseMode != wantVerboseMode {
		t.Errorf("Got: %t, want: %t", gotVerboseMode, wantVerboseMode)
	}

	if gotViewType != wantViewType {
		t.Errorf("Got: %v, want: %v", gotViewType, wantViewType)
	}

}
