package printer

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/stretchr/testify/assert"
	"sigs.k8s.io/yaml"
)

func TestNewYamlPrinter(t *testing.T) {
	yp := NewYamlPrinter()
	assert.NotNil(t, yp)
}

func TestSetWriter_Yaml(t *testing.T) {
	yp := NewYamlPrinter()
	assert.NotNil(t, yp)

	// Test without outputFile (should use stdout)
	yp.SetWriter(context.TODO(), "")
	assert.NotNil(t, yp.writer)
	yp.CloseWriter()
}

func TestScore_Yaml(t *testing.T) {
	tests := []struct {
		name  string
		score float32
		want  string
	}{
		{
			name:  "Score not an integer",
			score: 20.7,
			want:  "\nOverall compliance-score (100- Excellent, 0- All failed): 21\n",
		},
		{
			name:  "Fractional score below perfect",
			score: 99.5,
			want:  "\nOverall compliance-score (100- Excellent, 0- All failed): 99\n",
		},
		{
			name:  "Score less than 0",
			score: -20.0,
			want:  "\nOverall compliance-score (100- Excellent, 0- All failed): 0\n",
		},
		{
			name:  "Score greater than 100",
			score: 120.0,
			want:  "\nOverall compliance-score (100- Excellent, 0- All failed): 100\n",
		},
		{
			name:  "Score 50",
			score: 50.0,
			want:  "\nOverall compliance-score (100- Excellent, 0- All failed): 50\n",
		},
		{
			name:  "Zero Score",
			score: 0.0,
			want:  "\nOverall compliance-score (100- Excellent, 0- All failed): 0\n",
		},
		{
			name:  "Perfect Score",
			score: 100,
			want:  "\nOverall compliance-score (100- Excellent, 0- All failed): 100\n",
		},
	}

	yp := NewYamlPrinter()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.CreateTemp("", "pdfPrinter-score-output")
			if err != nil {
				panic(err)
			}
			defer func() {
				_ = f.Close()
			}()

			oldStderr := os.Stderr
			defer func() {
				os.Stderr = oldStderr
			}()
			os.Stderr = f

			yp.Score(tt.score)

			f.Seek(0, 0)
			got, err := io.ReadAll(f)
			if err != nil {
				panic(err)
			}
			assert.Equal(t, tt.want, string(got))
		})
	}
}

func TestActionPrint_Yaml(t *testing.T) {
	session := cautils.NewOPASessionObjMock()

	tmpYaml, err := os.CreateTemp("", "yaml-regression-*.yaml")
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(tmpYaml.Name())
	}()

	yp := NewYamlPrinter()
	yp.writer = tmpYaml
	yp.ActionPrint(context.Background(), session, nil)
	assert.NoError(t, tmpYaml.Close())

	rawYaml, err := os.ReadFile(tmpYaml.Name())
	assert.NoError(t, err)

	var gotYaml interface{}
	err = yaml.Unmarshal(rawYaml, &gotYaml)
	assert.NoError(t, err, "output must be valid YAML")

	tmpJson, err := os.CreateTemp("", "json-regression-*.json")
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(tmpJson.Name())
	}()

	jp := NewJsonPrinter("")
	jp.writer = tmpJson
	jp.ActionPrint(context.Background(), session, nil)
	assert.NoError(t, tmpJson.Close())

	rawJson, err := os.ReadFile(tmpJson.Name())
	assert.NoError(t, err)

	var gotJson interface{}
	err = json.Unmarshal(rawJson, &gotJson)
	assert.NoError(t, err, "output must be valid JSON")

	assert.Equal(t, gotJson, gotYaml)
}

func TestActionPrint_ImageScan_Yaml(t *testing.T) {
	// A populated []cautils.ImageScanData
	imageScanData := []cautils.ImageScanData{buildSeverityExceptionImageScanData()}

	tmpYaml, err := os.CreateTemp("", "yaml-imagescan-*.yaml")
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(tmpYaml.Name())
	}()

	yp := NewYamlPrinter()
	yp.writer = tmpYaml
	yp.ActionPrint(context.Background(), nil, imageScanData)
	assert.NoError(t, tmpYaml.Close())

	rawYaml, err := os.ReadFile(tmpYaml.Name())
	assert.NoError(t, err)

	var gotYaml interface{}
	err = yaml.Unmarshal(rawYaml, &gotYaml)
	assert.NoError(t, err, "output must be valid YAML")

	tmpJson, err := os.CreateTemp("", "json-imagescan-*.json")
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(tmpJson.Name())
	}()

	jp := NewJsonPrinter("")
	jp.writer = tmpJson
	jp.ActionPrint(context.Background(), nil, imageScanData)
	assert.NoError(t, tmpJson.Close())

	rawJson, err := os.ReadFile(tmpJson.Name())
	assert.NoError(t, err)

	var gotJson interface{}
	err = json.Unmarshal(rawJson, &gotJson)
	assert.NoError(t, err, "output must be valid JSON")

	assert.Equal(t, gotJson, gotYaml)
}
