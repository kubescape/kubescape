package cautils

import (
	"io"
	"os"
	"testing"

	"github.com/kubescape/go-logger"
	"github.com/stretchr/testify/assert"
)

func TestStartSpinner(t *testing.T) {
	tests := []struct {
		name        string
		loggerLevel string
		enabled     bool
	}{
		{
			name:        "TestStartSpinner - disabled",
			loggerLevel: "warning",
			enabled:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger.L().SetLevel(tt.loggerLevel)
			StartSpinner()
			if !tt.enabled {
				if spinner != nil {
					t.Errorf("spinner should be nil")
				}
			}
		})
	}
}

func TestFailureDisplay(t *testing.T) {
	tests := []struct {
		text string
		want string
	}{
		{
			text: "Test",
			want: "Test",
		},
		{
			text: "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			// Redirect stdout to a buffer
			rescueStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			FailureDisplay(os.Stdout, tt.text)

			w.Close()
			got, _ := io.ReadAll(r)
			os.Stdout = rescueStdout

			assert.Equal(t, tt.want, string(got))
		})
	}
}

func TestWarningDisplay(t *testing.T) {
	tests := []struct {
		text string
		want string
	}{
		{
			text: "Test",
			want: "Test",
		},
		{
			text: "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			// Redirect stdout to a buffer
			rescueStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			WarningDisplay(os.Stdout, tt.text)

			w.Close()
			got, _ := io.ReadAll(r)
			os.Stdout = rescueStdout

			assert.Equal(t, tt.want, string(got))
		})
	}
}

func TestFailureTextDisplay(t *testing.T) {
	tests := []struct {
		text string
		want string
	}{
		{
			text: "Test",
			want: "Test",
		},
		{
			text: "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			// Redirect stdout to a buffer
			rescueStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			FailureTextDisplay(os.Stdout, tt.text)

			w.Close()
			got, _ := io.ReadAll(r)
			os.Stdout = rescueStdout

			assert.Equal(t, tt.want, string(got))
		})
	}
}

func TestInfoDisplay(t *testing.T) {
	tests := []struct {
		text string
		want string
	}{
		{
			text: "Test",
			want: "Test",
		},
		{
			text: "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			// Redirect stdout to a buffer
			rescueStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			InfoDisplay(os.Stdout, tt.text)

			w.Close()
			got, _ := io.ReadAll(r)
			os.Stdout = rescueStdout

			assert.Equal(t, tt.want, string(got))
		})
	}
}

func TestInfoTextDisplay(t *testing.T) {
	tests := []struct {
		text string
		want string
	}{
		{
			text: "Test",
			want: "Test",
		},
		{
			text: "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			// Redirect stdout to a buffer
			rescueStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			InfoTextDisplay(os.Stdout, tt.text)

			w.Close()
			got, _ := io.ReadAll(r)
			os.Stdout = rescueStdout

			assert.Equal(t, tt.want, string(got))
		})
	}
}

func TestSimpleDisplay(t *testing.T) {
	tests := []struct {
		text string
		want string
	}{
		{
			text: "Test",
			want: "Test",
		},
		{
			text: "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			// Redirect stdout to a buffer
			rescueStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			SimpleDisplay(os.Stdout, tt.text)

			w.Close()
			got, _ := io.ReadAll(r)
			os.Stdout = rescueStdout

			assert.Equal(t, tt.want, string(got))
		})
	}
}

func TestSuccessDisplay(t *testing.T) {
	tests := []struct {
		text string
		want string
	}{
		{
			text: "Test",
			want: "Test",
		},
		{
			text: "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			// Redirect stdout to a buffer
			rescueStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			SuccessDisplay(os.Stdout, tt.text)

			w.Close()
			got, _ := io.ReadAll(r)
			os.Stdout = rescueStdout

			assert.Equal(t, tt.want, string(got))
		})
	}
}

func TestDescriptionDisplay(t *testing.T) {
	tests := []struct {
		text string
		want string
	}{
		{
			text: "Test",
			want: "Test",
		},
		{
			text: "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			// Redirect stdout to a buffer
			rescueStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			DescriptionDisplay(os.Stdout, tt.text)

			w.Close()
			got, _ := io.ReadAll(r)
			os.Stdout = rescueStdout

			assert.Equal(t, tt.want, string(got))
		})
	}
}

func TestBoldDisplay(t *testing.T) {
	tests := []struct {
		text string
		want string
	}{
		{
			text: "Test",
			want: "Test",
		},
		{
			text: "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			// Redirect stdout to a buffer
			rescueStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			BoldDisplay(os.Stdout, tt.text)

			w.Close()
			got, _ := io.ReadAll(r)
			os.Stdout = rescueStdout

			assert.Equal(t, tt.want, string(got))
		})
	}
}

func TestLineDisplay(t *testing.T) {
	tests := []struct {
		text string
		want string
	}{
		{
			text: "Test",
			want: "Test",
		},
		{
			text: "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			// Redirect stdout to a buffer
			rescueStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			LineDisplay(os.Stdout, tt.text)

			w.Close()
			got, _ := io.ReadAll(r)
			os.Stdout = rescueStdout

			assert.Equal(t, tt.want, string(got))
		})
	}
}

func TestSectionHeadingDisplay(t *testing.T) {
	tests := []struct {
		text string
		want string
	}{
		{
			text: "Test Section",
			want: "\nTest Section\n────────────\n\n",
		},
		{
			text: "",
			want: "\n\n\n\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			// Redirect stdout to a buffer
			rescueStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			SectionHeadingDisplay(os.Stdout, tt.text)

			w.Close()
			got, _ := io.ReadAll(r)
			os.Stdout = rescueStdout

			assert.Equal(t, tt.want, string(got))
		})
	}
}

func TestStarDisplay(t *testing.T) {
	tests := []struct {
		text string
		want string
	}{
		{
			text: "Test",
			want: "* Test",
		},
		{
			text: "",
			want: "* ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			// Redirect stdout to a buffer
			rescueStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			StarDisplay(os.Stdout, tt.text)

			w.Close()
			got, _ := io.ReadAll(r)
			os.Stdout = rescueStdout

			assert.Equal(t, tt.want, string(got))
		})
	}
}

// Returns a new instance of ProgressHandler with the given title.
func TestNewProgressHandler_(t *testing.T) {
	tests := []struct {
		title string
	}{
		{
			title: "Test title",
		},
		{
			title: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.title, func(t *testing.T) {
			progressHandler := NewProgressHandler(tt.title)
			assert.NotNil(t, progressHandler)

			assert.Equal(t, tt.title, progressHandler.title)
		})
	}
}
