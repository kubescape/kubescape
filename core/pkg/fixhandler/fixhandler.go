package fixhandler

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/armosec/armoapi-go/armotypes"
	metav1 "github.com/kubescape/kubescape/v2/core/meta/datastructures/v1"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/mikefarah/yq/v4/pkg/yqlib"
	"gopkg.in/op/go-logging.v1"
)

const UserValuePrefix = "YOUR_"

func NewFixHandler(fixInfo *metav1.FixInfo) (*FixHandler, error) {
	jsonFile, err := os.Open(fixInfo.ReportFile)
	if err != nil {
		return nil, err
	}
	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)

	var reportObj reporthandlingv2.PostureReport
	if err = json.Unmarshal(byteValue, &reportObj); err != nil {
		return nil, err
	}

	if err = isSupportedScanningTarget(&reportObj); err != nil {
		return nil, err
	}

	localPath := getLocalPath(&reportObj)
	if _, err = os.Stat(localPath); err != nil {
		return nil, err
	}

	backendLoggerLeveled := logging.AddModuleLevel(logging.NewLogBackend(logger.L().GetWriter(), "", 0))
	backendLoggerLeveled.SetLevel(logging.ERROR, "")
	yqlib.GetLogger().SetBackend(backendLoggerLeveled)

	return &FixHandler{
		fixInfo:       fixInfo,
		reportObj:     &reportObj,
		localBasePath: localPath,
	}, nil
}

func isSupportedScanningTarget(report *reporthandlingv2.PostureReport) error {
	if report.Metadata.ScanMetadata.ScanningTarget == reporthandlingv2.GitLocal || report.Metadata.ScanMetadata.ScanningTarget == reporthandlingv2.Directory {
		return nil
	}

	return fmt.Errorf("unsupported scanning target. Only local git and directory scanning targets are supported")
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

func (h *FixHandler) buildResourcesMap() map[string]*reporthandling.Resource {
	resourceIdToRawResource := make(map[string]*reporthandling.Resource)
	for i := range h.reportObj.Resources {
		resourceIdToRawResource[h.reportObj.Resources[i].GetID()] = &h.reportObj.Resources[i]
	}
	for i := range h.reportObj.Results {
		if h.reportObj.Results[i].RawResource == nil {
			continue
		}
		resourceIdToRawResource[h.reportObj.Results[i].RawResource.GetID()] = h.reportObj.Results[i].RawResource
	}

	return resourceIdToRawResource
}

func (h *FixHandler) getPathFromRawResource(obj map[string]interface{}) string {
	if localworkload.IsTypeLocalWorkload(obj) {
		localwork := localworkload.NewLocalWorkload(obj)
		return localwork.GetPath()
	} else if objectsenvelopes.IsTypeRegoResponseVector(obj) {
		regoResponseVectorObject := objectsenvelopes.NewRegoResponseVectorObject(obj)
		relatedObjects := regoResponseVectorObject.GetRelatedObjects()
		for _, relatedObject := range relatedObjects {
			if localworkload.IsTypeLocalWorkload(relatedObject.GetObject()) {
				return relatedObject.(*localworkload.LocalWorkload).GetPath()
			}
		}
	}

	return ""
}

func (h *FixHandler) PrepareResourcesToFix() []ResourceFixInfo {
	resourceIdToResource := h.buildResourcesMap()

	resourcesToFix := make([]ResourceFixInfo, 0)
	for _, result := range h.reportObj.Results {
		if !result.GetStatus(nil).IsFailed() {
			continue
		}

		resourceID := result.ResourceID
		resourceObj := resourceIdToResource[resourceID]
		resourcePath := h.getPathFromRawResource(resourceObj.GetObject())
		if resourcePath == "" {
			continue
		}

		if resourceObj.Source == nil || resourceObj.Source.FileType != reporthandling.SourceTypeYaml {
			continue
		}

		relativePath, documentIndex, err := h.getFilePathAndIndex(resourcePath)
		if err != nil {
			logger.L().Error("Skipping invalid resource path: " + resourcePath)
			continue
		}

		absolutePath := path.Join(h.localBasePath, relativePath)
		if _, err := os.Stat(absolutePath); err != nil {
			logger.L().Error("Skipping missing file: " + absolutePath)
			continue
		}

		rfi := ResourceFixInfo{
			FilePath:        absolutePath,
			Resource:        resourceObj,
			YamlExpressions: make(map[string]*armotypes.FixPath, 0),
			DocumentIndex:   documentIndex,
		}

		for i := range result.AssociatedControls {
			if result.AssociatedControls[i].GetStatus(nil).IsFailed() {
				rfi.addYamlExpressionsFromResourceAssociatedControl(documentIndex, &result.AssociatedControls[i], h.fixInfo.SkipUserValues)
			}
		}

		if len(rfi.YamlExpressions) > 0 {
			resourcesToFix = append(resourcesToFix, rfi)
		}
	}

	return resourcesToFix
}

func (h *FixHandler) PrintExpectedChanges(resourcesToFix []ResourceFixInfo) {
	var sb strings.Builder
	sb.WriteString("The following changes will be applied:\n")

	for _, resourceFixInfo := range resourcesToFix {
		sb.WriteString(fmt.Sprintf("File: %s\n", resourceFixInfo.FilePath))
		sb.WriteString(fmt.Sprintf("Resource: %s\n", resourceFixInfo.Resource.GetName()))
		sb.WriteString(fmt.Sprintf("Kind: %s\n", resourceFixInfo.Resource.GetKind()))
		sb.WriteString("Changes:\n")

		i := 1
		for _, fixPath := range resourceFixInfo.YamlExpressions {
			sb.WriteString(fmt.Sprintf("\t%d) %s = %s\n", i, (*fixPath).Path, (*fixPath).Value))
			i++
		}
		sb.WriteString("\n------\n")
	}

	logger.L().Info(sb.String())
}

func (h *FixHandler) ApplyChanges(resourcesToFix []ResourceFixInfo) (int, []error) {
	updatedFiles := make(map[string]bool)
	errors := make([]error, 0)

	fileYamlExpressions := h.getFileYamlExpressions(resourcesToFix)

	for filepath, yamlExpression := range fileYamlExpressions {
		fileAsString, err := getFileString(filepath)

		if err != nil {
			logger.L().Error(err.Error())
			continue
		}

		fixedYamlString, err := h.ApplyFix(fileAsString, yamlExpression)

		if err != nil {
			errors = append(errors, fmt.Errorf("failed to fix file %s: %w ", filepath, err))
			continue
		} else {
			updatedFiles[filepath] = true
		}

		err = writeFixesToFile(filepath, fixedYamlString)

		if err != nil {
			logger.L().Error(fmt.Sprintf("Cannot Apply fixes to file %s, %v", filepath, err.Error()))
			errors = append(errors, err)
		}
	}

	return len(updatedFiles), errors
}

func (h *FixHandler) getFilePathAndIndex(filePathWithIndex string) (filePath string, documentIndex int, err error) {
	splittedPath := strings.Split(filePathWithIndex, ":")
	if len(splittedPath) <= 1 {
		return "", 0, fmt.Errorf("expected to find ':' in file path")
	}

	filePath = splittedPath[0]
	if documentIndex, err := strconv.Atoi(splittedPath[1]); err != nil {
		return "", 0, err
	} else {
		return filePath, documentIndex, nil
	}
}

func (h *FixHandler) ApplyFix(yamlString, yamlExpression string) (fixedYamlString string, err error) {
	yamlLines := strings.Split(yamlString, "\n")

	originalRootNodes := decodeDocumentRoots(yamlString)
	fixedRootNodes, err := getFixedNodes(yamlString, yamlExpression)

	if err != nil {
		return "", err
	}

	contentsToAdd, linesToRemove := getFixInfo(originalRootNodes, fixedRootNodes)

	fixedYamlLines := getFixedYamlLines(yamlLines, contentsToAdd, linesToRemove)

	fixedYamlString = getStringFromSlice(fixedYamlLines)

	return fixedYamlString, nil
}

func (h *FixHandler) getFileYamlExpressions(resourcesToFix []ResourceFixInfo) map[string]string {
	fileYamlExpressions := make(map[string]string, 0)
	for _, resourceToFix := range resourcesToFix {
		singleExpression := reduceYamlExpressions(&resourceToFix)
		resourceFilePath := resourceToFix.FilePath

		if _, pathExistsInMap := fileYamlExpressions[resourceFilePath]; !pathExistsInMap {
			fileYamlExpressions[resourceFilePath] = singleExpression
		} else {
			fileYamlExpressions[resourceFilePath] = joinStrings(fileYamlExpressions[resourceFilePath], " | ", singleExpression)
		}

	}

	return fileYamlExpressions
}

func (rfi *ResourceFixInfo) addYamlExpressionsFromResourceAssociatedControl(documentIndex int, ac *resourcesresults.ResourceAssociatedControl, skipUserValues bool) {
	for _, rule := range ac.ResourceAssociatedRules {
		if !rule.GetStatus(nil).IsFailed() {
			continue
		}

		for _, rulePaths := range rule.Paths {
			if rulePaths.FixPath.Path == "" {
				continue
			}
			if strings.HasPrefix(rulePaths.FixPath.Value, UserValuePrefix) && skipUserValues {
				continue
			}

			yamlExpression := fixPathToValidYamlExpression(rulePaths.FixPath.Path, rulePaths.FixPath.Value, documentIndex)
			rfi.YamlExpressions[yamlExpression] = &rulePaths.FixPath
		}
	}
}

// reduceYamlExpressions reduces the number of yaml expressions to a single one
func reduceYamlExpressions(resource *ResourceFixInfo) string {
	expressions := make([]string, 0, len(resource.YamlExpressions))
	for expr := range resource.YamlExpressions {
		expressions = append(expressions, expr)
	}

	return strings.Join(expressions, " | ")
}

func fixPathToValidYamlExpression(fixPath, value string, documentIndexInYaml int) string {
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

func joinStrings(inputStrings ...string) string {
	return strings.Join(inputStrings, "")
}

func getFileString(filepath string) (string, error) {
	bytes, err := ioutil.ReadFile(filepath)

	if err != nil {
		return "", fmt.Errorf("Error reading file %s", filepath)
	}

	return string(bytes), nil
}

func writeFixesToFile(filepath, content string) error {
	err := ioutil.WriteFile(filepath, []byte(content), 0644)

	if err != nil {
		return fmt.Errorf("Error writing fixes to file: %w", err)
	}

	return nil
}
