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
	for _, resourceToFix := range resourcesToFix {
		singleExpression := reduceYamlExpressions(&resourceToFix)
		if err := h.applyFixToFile(resourceToFix.FilePath, singleExpression); err != nil {
			errors = append(errors,
				fmt.Errorf("failed to fix resource [Name: '%s', Kind: '%s'] in '%s': %w ",
					resourceToFix.Resource.GetName(),
					resourceToFix.Resource.GetKind(),
					resourceToFix.FilePath,
					err))
		} else {
			updatedFiles[resourceToFix.FilePath] = true
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

func (h *FixHandler) applyFixToFile(filePath, yamlExpression string) (cmdError error) {

	// While obtaining fixedYamlNode, comments and empty lines at the top are ignored. In order to deal with that,
	// comments and empty lines are removed and they are inserted again when applying fixes to file.
	contentAtHead, err := truncateContentAtHead(filePath)

	if err != nil {
		logger.L().Fatal("Error truncating comments and empty lines at head")
	}
	originalYamlNode := constructDecodedYaml(filePath)
	fixedYamlNode := constructFixedYamlNode(filePath, yamlExpression)

	originalList := constructDFSOrder(originalYamlNode)
	fixedList := constructDFSOrder(fixedYamlNode)

	contentToAdd, linesToRemove := getFixInfo(originalList, fixedList)

	err = applyFixesToFile(filePath, contentToAdd, linesToRemove, contentAtHead)
	return err
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
