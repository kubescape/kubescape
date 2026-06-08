package cautils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ---------------------------------------------------------------------------
// BoolPtrFlag
// ---------------------------------------------------------------------------

func TestBoolPtrFlag_Type(t *testing.T) {
	bpf := BoolPtrFlag{}
	assert.Equal(t, "bool", bpf.Type())
}

func TestBoolPtrFlag_String(t *testing.T) {
	tests := []struct {
		name string
		flag BoolPtrFlag
		want string
	}{
		{
			name: "nil pointer returns empty string",
			flag: BoolPtrFlag{},
			want: "",
		},
		{
			name: "true value",
			flag: NewBoolPtr(boolPtr(true)),
			want: "true",
		},
		{
			name: "false value",
			flag: NewBoolPtr(boolPtr(false)),
			want: "false",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.flag.String())
		})
	}
}

func TestBoolPtrFlag_Get(t *testing.T) {
	t.Run("nil when uninitialized", func(t *testing.T) {
		bpf := BoolPtrFlag{}
		assert.Nil(t, bpf.Get())
	})

	t.Run("returns underlying pointer", func(t *testing.T) {
		b := true
		bpf := NewBoolPtr(&b)
		got := bpf.Get()
		assert.NotNil(t, got)
		assert.True(t, *got)
	})
}

func TestBoolPtrFlag_GetBool(t *testing.T) {
	tests := []struct {
		name string
		flag BoolPtrFlag
		want bool
	}{
		{
			name: "nil pointer returns false",
			flag: BoolPtrFlag{},
			want: false,
		},
		{
			name: "true pointer returns true",
			flag: NewBoolPtr(boolPtr(true)),
			want: true,
		},
		{
			name: "false pointer returns false",
			flag: NewBoolPtr(boolPtr(false)),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.flag.GetBool())
		})
	}
}

// ---------------------------------------------------------------------------
// isHTTPURL
// ---------------------------------------------------------------------------
func TestNewBoolPtr(t *testing.T) {
	t.Run("with non-nil pointer", func(t *testing.T) {
		b := true
		bpf := NewBoolPtr(&b)
		assert.NotNil(t, bpf.Get())
		assert.True(t, bpf.GetBool())
	})

	t.Run("with nil pointer", func(t *testing.T) {
		bpf := NewBoolPtr(nil)
		assert.Nil(t, bpf.Get())
		assert.False(t, bpf.GetBool())
	})
}

func TestIsHTTPURL(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"https URL", "https://example.com/repo", true},
		{"http URL", "http://example.com/repo", true},
		{"git SSH URL", "git@github.com:org/repo.git", false},
		{"local path", "/home/user/project", false},
		{"relative path", "some/dir", false},
		{"empty string", "", false},
		{"ftp URL", "ftp://example.com/file", false},
		{"https with port", "https://gitlab.local:8443/org/repo", true},
		{"http with path and query", "http://example.com/path?q=1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isHTTPURL(tt.input))
		})
	}
}

// ---------------------------------------------------------------------------
// unique
// ---------------------------------------------------------------------------

func TestUnique(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  []string
	}{
		{
			name:  "no duplicates",
			input: []string{"a", "b", "c"},
			want:  []string{"a", "b", "c"},
		},
		{
			name:  "all duplicates",
			input: []string{"x", "x", "x"},
			want:  []string{"x"},
		},
		{
			name:  "preserves first occurrence order",
			input: []string{"b", "a", "b", "c", "a"},
			want:  []string{"b", "a", "c"},
		},
		{
			name:  "empty slice",
			input: []string{},
			want:  []string{},
		},
		{
			name:  "single element",
			input: []string{"only"},
			want:  []string{"only"},
		},
		{
			name:  "nil slice",
			input: nil,
			want:  []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := unique(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ---------------------------------------------------------------------------
// ScanInfo.GetInputFiles
// ---------------------------------------------------------------------------

func TestScanInfo_GetInputFiles(t *testing.T) {
	tests := []struct {
		name          string
		inputPatterns []string
		want          string
	}{
		{
			name:          "returns first pattern",
			inputPatterns: []string{"/path/to/file.yaml", "/other/file.yaml"},
			want:          "/path/to/file.yaml",
		},
		{
			name:          "empty patterns returns empty string",
			inputPatterns: []string{},
			want:          "",
		},
		{
			name:          "nil patterns returns empty string",
			inputPatterns: nil,
			want:          "",
		},
		{
			name:          "single pattern",
			inputPatterns: []string{"manifest.yaml"},
			want:          "manifest.yaml",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanInfo := &ScanInfo{InputPatterns: tt.inputPatterns}
			assert.Equal(t, tt.want, scanInfo.GetInputFiles())
		})
	}
}

// ---------------------------------------------------------------------------
// ScanInfo.Cleanup / AddCleanup
// ---------------------------------------------------------------------------

func TestScanInfo_Cleanup(t *testing.T) {
	t.Run("runs all registered cleanup functions", func(t *testing.T) {
		var calls []int
		scanInfo := &ScanInfo{}
		scanInfo.AddCleanup(func() { calls = append(calls, 1) })
		scanInfo.AddCleanup(func() { calls = append(calls, 2) })
		scanInfo.AddCleanup(func() { calls = append(calls, 3) })

		scanInfo.Cleanup()

		assert.Equal(t, []int{1, 2, 3}, calls)
	})

	t.Run("no-op when no cleanups registered", func(t *testing.T) {
		scanInfo := &ScanInfo{}
		assert.NotPanics(t, func() { scanInfo.Cleanup() })
	})
}

// ---------------------------------------------------------------------------
// ScanInfo.SetScanType
// ---------------------------------------------------------------------------

func TestScanInfo_SetScanType(t *testing.T) {
	scanInfo := &ScanInfo{}
	scanInfo.SetScanType(ScanTypeCluster)
	assert.Equal(t, ScanTypeCluster, scanInfo.ScanType)

	scanInfo.SetScanType(ScanTypeImage)
	assert.Equal(t, ScanTypeImage, scanInfo.ScanType)
}

// ---------------------------------------------------------------------------
// ScanInfo.contains (unexported helper)
// ---------------------------------------------------------------------------

func TestScanInfo_contains(t *testing.T) {
	scanInfo := &ScanInfo{
		PolicyIdentifier: []PolicyIdentifier{
			{Identifier: "nsa"},
			{Identifier: "mitre"},
		},
	}

	assert.True(t, scanInfo.contains("nsa"))
	assert.True(t, scanInfo.contains("mitre"))
	assert.False(t, scanInfo.contains("cis"))
	assert.False(t, scanInfo.contains(""))
}

// ---------------------------------------------------------------------------
// helper
// ---------------------------------------------------------------------------

func boolPtr(b bool) *bool {
	return &b
}
