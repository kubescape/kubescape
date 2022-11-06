package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strconv"
	"strings"

	// "github.com/armosec/opa-utils/reporthandling"

	"github.com/armosec/utils-go/boolutils"
	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/mikefarah/yq/v4/pkg/yqlib"
	"gopkg.in/op/go-logging.v1"
)

func (ks *Kubescape) Fix(reportPath string) error {
	jsonFile, err := os.Open(reportPath)
	if err != nil {
		fmt.Println(err)
	}
	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)

	var reportObj reporthandlingv2.PostureReport
	if err := json.Unmarshal(byteValue, &reportObj); err != nil {
		return err
	}

	if err := isSupportedScanningTarget(&reportObj); err != nil {
		return err
	}

	localPath := getLocalPath(&reportObj)

	if _, err := os.Stat(localPath); err == nil {
		fixResourcesInFiles(&reportObj, localPath)
	} else if errors.Is(err, os.ErrNotExist) {
		return err
	} else {
		return err
	}

	return nil
}

func isSupportedScanningTarget(report *reporthandlingv2.PostureReport) error {
	if report.Metadata.ScanMetadata.ScanningTarget == reporthandlingv2.GitLocal || report.Metadata.ScanMetadata.ScanningTarget == reporthandlingv2.Directory {
		return nil
	}

	return fmt.Errorf("unsupported scanning target")
}

func getLocalPath(report *reporthandlingv2.PostureReport) string {
	if report.Metadata.ScanMetadata.ScanningTarget == reporthandlingv2.GitLocal {
		return report.Metadata.ContextMetadata.RepoContextMetadata.LocalRootPath
	}

	if report.Metadata.ScanMetadata.ScanningTarget == reporthandlingv2.Directory {
		return report.Metadata.ContextMetadata.DirectoryContextMetadata.BasePath
	}

	return ""
}

func getLocalWorkloadPathsFromResources(resources []reporthandling.Resource) map[string]string {
	resourceIdToPath := make(map[string]string)

	for i := range resources {
		obj := resources[i].GetObject()
		if localworkload.IsTypeLocalWorkload(obj) {
			localwork := localworkload.NewLocalWorkload(obj)
			path := localwork.GetPath()
			if path != "" {
				resourceIdToPath[resources[i].ResourceID] = path
			}
		} else if objectsenvelopes.IsTypeRegoResponseVector(obj) {
			regoResponseVectorObject := objectsenvelopes.NewRegoResponseVectorObject(obj)
			relatedObjects := regoResponseVectorObject.GetRelatedObjects()
			for _, relatedObject := range relatedObjects {
				if localworkload.IsTypeLocalWorkload(relatedObject.GetObject()) {
					path := relatedObject.(*localworkload.LocalWorkload).GetPath()
					if path != "" {
						resourceIdToPath[resourceIdToPath[resources[i].ResourceID]] = path
					}
				}
			}
		}
	}

	return resourceIdToPath
}

func fixResourcesInFiles(reportObj *reporthandlingv2.PostureReport, basePath string) {
	resourceIdToPath := getLocalWorkloadPathsFromResources(reportObj.Resources)

	for _, result := range reportObj.Results {
		if !result.GetStatus(nil).IsFailed() {
			continue
		}

		resourceID := result.ResourceID
		resourcePath, pathExists := resourceIdToPath[resourceID]
		if !pathExists {
			continue
		}

		relativePath, documentIndex, err := getFilePathAndIndex(resourcePath)
		if err != nil {
			continue
		}

		rsrcAbsPath := path.Join(basePath, relativePath)
		if _, err := os.Stat(rsrcAbsPath); err != nil {
			continue
		}

		yamlExpressions := make([]string, 0)
		for i := range result.AssociatedControls {
			if result.AssociatedControls[i].GetStatus(nil).IsFailed() {
				res := getYamlExpressionsFromResourceAssociatedControl(documentIndex, &result.AssociatedControls[i])
				yamlExpressions = append(yamlExpressions, res...)
			}
		}

		if len(yamlExpressions) > 0 {
			fmt.Println("fixing ", resourceID, " in ", rsrcAbsPath, ":")
			fixExpressions := removeDuplicates(yamlExpressions)
			for _, fixExpression := range fixExpressions {
				fmt.Println("    > ", fixExpression)
			}
			singleExpression := combineYamlExpressions(fixExpressions)
			err := fixFile(rsrcAbsPath, singleExpression)
			if err != nil {
				fmt.Println("failed to fix ", resourceID, " in ", rsrcAbsPath, ": ", err)
			}
		}
	}
}

func getFilePathAndIndex(filePathWithIndex string) (string, int, error) {
	splittedPath := strings.Split(filePathWithIndex, ":")
	if len(splittedPath) <= 1 {
		return "", 0, fmt.Errorf("expected to find ':' in file path")
	}

	filePath := splittedPath[0]
	if documentIndex, err := strconv.Atoi(splittedPath[1]); err != nil {
		return "", 0, err
	} else {
		return filePath, documentIndex, nil
	}
}

func getYamlExpressionsFromResourceAssociatedControl(documentIndex int, ac *resourcesresults.ResourceAssociatedControl) []string {
	yamlExpressions := []string{}

	skipUserValue := false
	if v, ok := os.LookupEnv("SKIP_USER_VALUE"); ok && boolutils.StringToBool(v) {
		skipUserValue = true
	}

	for _, rule := range ac.ResourceAssociatedRules {
		if !rule.GetStatus(nil).IsFailed() {
			continue
		}

		for _, rulePaths := range rule.Paths {
			// if rulePaths.FailedPath != "" {
			// yamlExpressions = append(yamlExpressions, FailedPathToValidYamlExpression(rulePaths.FailedPath, documentIndex))
			if rulePaths.FixPath.Path != "" {
				if rulePaths.FixPath.Value == "YOUR_VALUE" && skipUserValue {
					continue
				}

				yamlExpressions = append(yamlExpressions, FixPathToValidYamlExpression(rulePaths.FixPath.Path, rulePaths.FixPath.Value, documentIndex))
			}
		}
	}
	return yamlExpressions
}

func combineYamlExpressions(yamlExpressions []string) string {
	return strings.Join(yamlExpressions, " | ")
}

func fixFile(filePath, yamlExpression string) (cmdError error) {
	var completedSuccessfully bool
	writeInPlaceHandler := yqlib.NewWriteInPlaceHandler(filePath)
	out, err := writeInPlaceHandler.CreateTempFile()
	if err != nil {
		panic(fmt.Sprintf("Unable to create a tmp file for in-place YAML update! %s", err))
	}
	defer func() {
		if cmdError == nil {
			cmdError = writeInPlaceHandler.FinishWriteInPlace(completedSuccessfully)
		}
	}()

	encoder := yqlib.NewYamlEncoder(2, false, yqlib.ConfiguredYamlPreferences)

	printer := yqlib.NewPrinter(encoder, yqlib.NewSinglePrinterWriter(out))
	allAtOnceEvaluator := yqlib.NewAllAtOnceEvaluator()

	backendLoggerLeveled := logging.AddModuleLevel(logging.NewLogBackend(logger.L().GetWriter(), "", 0))
	backendLoggerLeveled.SetLevel(logging.ERROR, "")
	yqlib.GetLogger().SetBackend(backendLoggerLeveled)

	prefs := yqlib.ConfiguredYamlPreferences
	prefs.EvaluateTogether = true
	decoder := yqlib.NewYamlDecoder(prefs)

	err = allAtOnceEvaluator.EvaluateFiles(yamlExpression, []string{filePath}, printer, decoder)

	completedSuccessfully = err == nil

	return err
}

// TODO: Add yaml comment "fixed by kubescape"?

// A fix path is a path to be updated/created
func FixPathToValidYamlExpression(fixPath, value string, documentIndexInYaml int) string {
	isStringValue := true
	if _, err := strconv.ParseBool(value); err == nil {
		isStringValue = false
	} else if _, err := strconv.ParseFloat(value, 64); err == nil {
		isStringValue = false
	} else if _, err := strconv.Atoi(value); err == nil {
		isStringValue = false
	}

	// Strings should be quoted
	if isStringValue {
		value = fmt.Sprintf("\"%s\"", value)
	}

	// select document index and add a dot for the root node
	return fmt.Sprintf("select(di==%d).%s |= %s", documentIndexInYaml, fixPath, value)
}

// // A failed path is a path to be removed
// func FailedPathToValidYamlExpression(failedPath string, documentIndexInYaml int) string {
// 	// select document index and add a dot for the root node
// 	return fmt.Sprintf("del(select(di==%d).%s)", documentIndexInYaml, failedPath)
// }

func removeDuplicates[T string | int](sliceList []T) []T {
	allKeys := make(map[T]bool)
	list := []T{}
	for _, item := range sliceList {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}
