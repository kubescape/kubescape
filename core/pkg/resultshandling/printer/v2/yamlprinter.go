package printer

import (
	"context"
	"encoding/json"
	"sigs.k8s.io/yaml"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/anchore/grype/grype/presenter"
	"github.com/anchore/grype/grype/presenter/models"
	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer"
)

const (
	yamlOutputFile = "report"
	yamlOutputExt  = ".yaml"
)

var _ printer.IPrinter = &YamlPrinter{}

type YamlPrinter struct {
	writer *os.File
}

func NewYamlPrinter() *YamlPrinter {
	return &YamlPrinter{}
}

func (yp *YamlPrinter) SetWriter(ctx context.Context, outputFile string) {
	if strings.TrimSpace(outputFile) == "" {
		outputFile = yamlOutputFile
	}
	if filepath.Ext(strings.TrimSpace(outputFile)) != yamlOutputExt {
		outputFile = outputFile + yamlOutputExt
	}
	yp.writer = printer.GetWriter(ctx, outputFile)
}

func (yp *YamlPrinter) Score(score float32) {
	fmt.Fprintf(os.Stderr, "\nOverall compliance-score (100- Excellent, 0- All failed): %d\n", cautils.Float32ToInt(score))

}

func jsonToYAML() () {
    // Convert the JSON data in the report.yaml file to YAML data.
	fileName := yamlOutputFile + yamlOutputExt;
	jsonData, err := ioutil.ReadFile(fileName)
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		return
	}

	var data interface{}

	if err := yaml.Unmarshal(jsonData, &data); err != nil {
		return
	}

	yamlData, err := yaml.Marshal(data)
	if err != nil {
		return
	}

	// Overwrite the file with the new YAML content
	err = ioutil.WriteFile(fileName, yamlData, os.ModePerm)
	if err != nil {
		fmt.Printf("Error writing YAML to file: %v\n", err)
		return
	}
}

func (yp *YamlPrinter) ActionPrint(ctx context.Context, opaSessionObj *cautils.OPASessionObj, imageScanData []cautils.ImageScanData) {
	var err error
	if opaSessionObj != nil {
		err = printYamlConfigurationsScanning(opaSessionObj, ctx, yp)
	} else if imageScanData != nil {
		err = yp.PrintImageScan(ctx, imageScanData[0].PresenterConfig)
	} else {
		err = fmt.Errorf("no data provided")
	}

	if err != nil {
		logger.L().Ctx(ctx).Error("failed to write results in yaml format", helpers.Error(err))
		return
	}

	// Convert JSON to YAML
	jsonToYAML()

	printer.LogOutputFile(yp.writer.Name())
}

func printYamlConfigurationsScanning(opaSessionObj *cautils.OPASessionObj, ctx context.Context, yp *YamlPrinter) error {
	r, err := json.Marshal(FinalizeResults(opaSessionObj))
	if err != nil {
		return err
	}

	_, err = yp.writer.Write(r)
	return err
}

func (yp *YamlPrinter) PrintImageScan(ctx context.Context, scanResults *models.PresenterConfig) error {
	if scanResults == nil {
		return fmt.Errorf("no image vulnerability data provided")
	}

    // Since grype/presenter doesn't have yaml config, use JSON config.
	presenterConfig, err := presenter.ValidatedConfig("json", "", false)
	if err != nil {
		return err
	}

	pres := presenter.GetPresenter(presenterConfig, *scanResults)

	return pres.Present(yp.writer)
}

func (yp *YamlPrinter) PrintNextSteps() {

}
