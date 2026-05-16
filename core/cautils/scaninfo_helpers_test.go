package cautils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBoolPtrFlag(t *testing.T) {
	t.Run("NewBoolPtr", func(t *testing.T) {
		b := true
		bpf := NewBoolPtr(&b)
		assert.Equal(t, &b, bpf.valPtr)
	})

	t.Run("Type", func(t *testing.T) {
		bpf := BoolPtrFlag{}
		assert.Equal(t, "bool", bpf.Type())
	})

	t.Run("String", func(t *testing.T) {
		b := true
		bpf := NewBoolPtr(&b)
		assert.Equal(t, "true", bpf.String())

		bpfNil := BoolPtrFlag{}
		assert.Equal(t, "", bpfNil.String())
	})

	t.Run("Get", func(t *testing.T) {
		b := true
		bpf := NewBoolPtr(&b)
		assert.Equal(t, &b, bpf.Get())
	})

	t.Run("GetBool", func(t *testing.T) {
		b := true
		bpf := NewBoolPtr(&b)
		assert.True(t, bpf.GetBool())

		bpfNil := BoolPtrFlag{}
		assert.False(t, bpfNil.GetBool())
	})

	t.Run("SetBool", func(t *testing.T) {
		bpf := BoolPtrFlag{}
		bpf.SetBool(true)
		assert.True(t, bpf.GetBool())
	})

	t.Run("Set", func(t *testing.T) {
		bpf := BoolPtrFlag{}
		err := bpf.Set("true")
		assert.NoError(t, err)
		assert.True(t, bpf.GetBool())

		err = bpf.Set("false")
		assert.NoError(t, err)
		assert.False(t, bpf.GetBool())
		
		err = bpf.Set("other")
		assert.NoError(t, err)
		assert.False(t, bpf.GetBool())
	})
}

func TestUnique(t *testing.T) {
	tests := []struct {
		name  string
		items []string
		want  []string
	}{
		{
			name:  "empty",
			items: []string{},
			want:  []string{},
		},
		{
			name:  "no duplicates",
			items: []string{"a", "b", "c"},
			want:  []string{"a", "b", "c"},
		},
		{
			name:  "with duplicates",
			items: []string{"a", "b", "a", "c", "b"},
			want:  []string{"a", "b", "c"},
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

func TestBoolPtrFlag_SetBool(t *testing.T) {
	bpf := BoolPtrFlag{}
	assert.Nil(t, bpf.Get(), "should start as nil")

	bpf.SetBool(true)
	assert.NotNil(t, bpf.Get())
	assert.True(t, bpf.GetBool())

	bpf.SetBool(false)
	assert.NotNil(t, bpf.Get())
	assert.False(t, bpf.GetBool())
}

func TestBoolPtrFlag_Set(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantErr  bool
		wantNil  bool
		wantBool bool
	}{
		{
			name:     "set to true",
			input:    "true",
			wantErr:  false,
			wantNil:  false,
			wantBool: true,
		},
		{
			name:     "set to false",
			input:    "false",
			wantErr:  false,
			wantNil:  false,
			wantBool: false,
		},
		{
			name:    "unrecognized value returns error",
			input:   "maybe",
			wantErr: true,
			wantNil: true,
		},
		{
			name:    "empty string returns error",
			input:   "",
			wantErr: true,
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := unique(tt.items)
			assert.Equal(t, tt.want, got)
		})
	}
}


			bpf := BoolPtrFlag{}
			err := bpf.Set(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			if tt.wantNil {
				assert.Nil(t, bpf.Get())
			} else {
				assert.NotNil(t, bpf.Get())
				assert.Equal(t, tt.wantBool, bpf.GetBool())
			}
		})
	}
}

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

// ---------------------------------------------------------------------------
// isHTTPURL
// ---------------------------------------------------------------------------

func TestIsHTTPURL(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "http",
			input: "http://example.com",
			want:  true,
		},
		{
			name:  "https",
			input: "https://example.com",
			want:  true,
		},
		{
			name:  "ftp",
			input: "ftp://example.com",
			want:  false,
		},
		{
			name:  "file path",
			input: "/path/to/file",
			want:  false,
		},
		{
			name:  "empty",
			input: "",
			want:  false,
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
			got := isHTTPURL(tt.input)
			got := unique(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestFormats(t *testing.T) {
	tests := []struct {
		name     string
		scanInfo *ScanInfo
		want     []string
	}{
		{
			name: "empty",
			scanInfo: &ScanInfo{
				Format: "",
			},
			want: []string{},
		},
		{
			name: "single format",
			scanInfo: &ScanInfo{
				Format: "json",
			},
			want: []string{"json"},
		},
		{
			name: "multiple formats",
			scanInfo: &ScanInfo{
				Format: "json,pdf",
			},
			want: []string{"json", "pdf"},
		},
		{
			name: "with spaces",
			scanInfo: &ScanInfo{
				Format: "json, pdf ,  html ",
			},
			want: []string{"json", "pdf", "html"},
		},
		{
			name: "with duplicates",
			scanInfo: &ScanInfo{
				Format: "json, pdf, json",
			},
			want: []string{"json", "pdf"},
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
			got := tt.scanInfo.Formats()
			assert.ElementsMatch(t, tt.want, got)
		})
	}
}

func TestContains(t *testing.T) {
	scanInfo := &ScanInfo{
		PolicyIdentifier: []PolicyIdentifier{
			{Identifier: "c-0012", Kind: "Control"},
			{Identifier: "nsa", Kind: "Framework"},
		},
	}

	assert.True(t, scanInfo.contains("c-0012"))
	assert.True(t, scanInfo.contains("nsa"))
	assert.False(t, scanInfo.contains("non-existent"))
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
