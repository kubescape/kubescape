package core

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"os"
	"regexp"
	"testing"

	"github.com/jwalton/gchalk"
	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var ansiRegex = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

func setupColorTest(t *testing.T) {
	t.Helper()
	oldLevel := gchalk.GetLevel()
	t.Cleanup(func() {
		gchalk.SetLevel(oldLevel)
	})
	gchalk.SetLevel(gchalk.LevelAnsi256)
	t.Setenv("FORCE_COLOR", "1")
}

func TestPrettyPrintControls_HeadersAreBold(t *testing.T) {
	setupColorTest(t)
	ctx := context.Background()
	entries := []metav1.ControlListEntry{
		{ID: "C-0001", Name: "Control 1", Frameworks: []string{"NSA"}},
	}

	got := captureStdout(t, func() {
		prettyPrintControls(ctx, entries)
	})

	assert.Contains(t, got, gchalk.WithBrightWhite().Bold("Control ID"))
	assert.Contains(t, got, gchalk.WithBrightWhite().Bold("Control name"))
	assert.Contains(t, got, gchalk.WithBrightWhite().Bold("Docs"))
	assert.Contains(t, got, gchalk.WithBrightWhite().Bold("Frameworks"))
}

func TestPrettyPrintControls_IDsAreCyan(t *testing.T) {
	setupColorTest(t)
	ctx := context.Background()
	entries := []metav1.ControlListEntry{
		{ID: "C-0001", Name: "Control 1", Frameworks: []string{"NSA"}},
	}

	got := captureStdout(t, func() {
		prettyPrintControls(ctx, entries)
	})

	assert.Contains(t, got, gchalk.WithBrightCyan().Bold("C-0001"))
	assert.Contains(t, got, gchalk.Cyan("https://hub.armosec.io/docs/c-0001"))
}

func TestPrettyPrintListFormat_FrameworksColored(t *testing.T) {
	setupColorTest(t)
	ctx := context.Background()
	policies := []string{"nsa", "mitre"}

	got := captureStdout(t, func() {
		prettyPrintListFormat(ctx, "frameworks", policies)
	})

	assert.Contains(t, got, gchalk.WithBrightWhite().Bold("Supported frameworks"))
	assert.Contains(t, got, gchalk.WithBrightCyan().Bold("nsa"))
	assert.Contains(t, got, gchalk.WithBrightCyan().Bold("mitre"))
}

func TestPrettyPrintControlsConfig_UnsetIsYellow(t *testing.T) {
	setupColorTest(t)
	ctx := context.Background()
	entries := []metav1.ControlConfigEntry{
		{
			Name:     "settings.key",
			Title:    "Settings Key",
			Values:   []string{},
			Controls: []string{"C-0001"},
		},
		{
			Name:     "settings.configured",
			Title:    "Configured Key",
			Values:   []string{"val1", "val2"},
			Controls: []string{"C-0002"},
		},
	}

	got := captureStdout(t, func() {
		prettyPrintControlsConfig(ctx, entries)
	})

	assert.Contains(t, got, gchalk.WithBrightWhite().Bold("Key"))
	assert.Contains(t, got, gchalk.WithBrightCyan().Bold("settings.key"))
	assert.Contains(t, got, gchalk.Yellow("<unset>"))
	assert.Contains(t, got, gchalk.WithBrightCyan().Bold("settings.configured"))
	assert.Contains(t, got, "val1")
	assert.Contains(t, got, gchalk.Cyan("C-0001"))
}

func TestPrettyPrint_NoColor_ListControls(t *testing.T) {
	oldLevel := gchalk.GetLevel()
	defer gchalk.SetLevel(oldLevel)

	t.Setenv("NO_COLOR", "1")
	t.Setenv("FORCE_COLOR", "0")
	gchalk.SetLevel(gchalk.LevelNone)

	ctx := context.Background()
	entries := []metav1.ControlListEntry{
		{ID: "C-0001", Name: "Control 1", Frameworks: []string{"NSA"}},
	}
	configEntries := []metav1.ControlConfigEntry{
		{Name: "settings.key", Title: "Title", Values: []string{}, Controls: []string{"C-0001"}},
	}

	gotControls := captureStdout(t, func() {
		prettyPrintControls(ctx, entries)
	})
	assert.False(t, ansiRegex.MatchString(gotControls), "controls output should not have ANSI escape codes when NO_COLOR is set")

	gotFrameworks := captureStdout(t, func() {
		prettyPrintListFormat(ctx, "frameworks", []string{"nsa", "mitre"})
	})
	assert.False(t, ansiRegex.MatchString(gotFrameworks), "frameworks output should not have ANSI escape codes when NO_COLOR is set")

	gotConfigs := captureStdout(t, func() {
		prettyPrintControlsConfig(ctx, configEntries)
	})
	assert.False(t, ansiRegex.MatchString(gotConfigs), "controls-config output should not have ANSI escape codes when NO_COLOR is set")
}

func TestJSONFormat_NoANSI(t *testing.T) {
	setupColorTest(t)

	controls := []metav1.ControlListEntry{
		{ID: "C-0001", Name: "Control 1", Frameworks: []string{"NSA"}},
	}
	gotControls := captureStdout(t, func() {
		jsonControlsFormat(controls)
	})
	assert.False(t, ansiRegex.MatchString(gotControls), "JSON controls output should not contain ANSI sequences")
	var parsedControls []map[string]interface{}
	err := json.Unmarshal([]byte(gotControls), &parsedControls)
	require.NoError(t, err, "JSON controls output must be valid JSON")

	configs := []metav1.ControlConfigEntry{
		{Name: "key", Title: "title", Values: []string{"val"}, Controls: []string{"C-0001"}},
	}
	gotConfigs := captureStdout(t, func() {
		jsonControlsConfigFormat(configs)
	})
	assert.False(t, ansiRegex.MatchString(gotConfigs), "JSON controls-config output should not contain ANSI sequences")
	var parsedConfigs []map[string]interface{}
	err = json.Unmarshal([]byte(gotConfigs), &parsedConfigs)
	require.NoError(t, err, "JSON controls-config output must be valid JSON")
}

func TestCSVFormat_NoANSI(t *testing.T) {
	setupColorTest(t)

	controls := []metav1.ControlListEntry{
		{ID: "C-0001", Name: "Control 1", Frameworks: []string{"NSA"}},
	}
	gotControls := captureStdout(t, func() {
		csvControlsFormat(controls)
	})
	assert.False(t, ansiRegex.MatchString(gotControls), "CSV controls output should not contain ANSI sequences")
	r := csv.NewReader(bytes.NewBufferString(gotControls))
	records, err := r.ReadAll()
	require.NoError(t, err, "CSV controls output must be valid CSV")
	assert.NotEmpty(t, records)

	configs := []metav1.ControlConfigEntry{
		{Name: "key", Title: "title", Values: []string{"val"}, Controls: []string{"C-0001"}},
	}
	gotConfigs := captureStdout(t, func() {
		csvControlsConfigFormat(configs)
	})
	assert.False(t, ansiRegex.MatchString(gotConfigs), "CSV controls-config output should not contain ANSI sequences")
	rConf := csv.NewReader(bytes.NewBufferString(gotConfigs))
	recordsConf, err := rConf.ReadAll()
	require.NoError(t, err, "CSV controls-config output must be valid CSV")
	assert.NotEmpty(t, recordsConf)
}

func TestPrettyPrintControls_DestinationFileNotTerminal(t *testing.T) {
	oldLevel := gchalk.GetLevel()
	defer gchalk.SetLevel(oldLevel)
	gchalk.SetLevel(gchalk.LevelAnsi256)

	t.Setenv("FORCE_COLOR", "0")
	_ = os.Unsetenv("FORCE_COLOR")
	_ = os.Unsetenv("NO_COLOR")

	tmpFile, err := os.CreateTemp("", "ks-list-test-*")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	rescueStdout := os.Stdout
	os.Stdout = tmpFile
	defer func() {
		os.Stdout = rescueStdout
	}()

	ctx := context.Background()
	entries := []metav1.ControlListEntry{
		{ID: "C-0001", Name: "Control 1", Frameworks: []string{"NSA"}},
	}

	prettyPrintControls(ctx, entries)

	data, err := os.ReadFile(tmpFile.Name())
	require.NoError(t, err)

	assert.False(t, ansiRegex.MatchString(string(data)), "output redirected to file should not contain ANSI sequences")
}
