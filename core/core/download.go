package core

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v2/core/cautils/getter"
	metav1 "github.com/kubescape/kubescape/v2/core/meta/datastructures/v1"
	"github.com/olekukonko/tablewriter"

	armosecadaptorv1 "github.com/kubescape/kubescape/v2/core/pkg/registryadaptors/armosec/v1"
	"github.com/kubescape/kubescape/v2/core/pkg/registryadaptors/registryvulnerabilities"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer"
	v2 "github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer/v2"
)

const (
	TargetControlsInputs = "controls-inputs"
	TargetExceptions     = "exceptions"
	TargetControl        = "control"
	TargetFramework      = "framework"
	TargetArtifacts      = "artifacts"
	TargetAttackTracks   = "attack-tracks"
)

var downloadFunc = map[string]func(*metav1.DownloadInfo) error{
	TargetControlsInputs: downloadConfigInputs,
	TargetExceptions:     downloadExceptions,
	TargetControl:        downloadControl,
	TargetFramework:      downloadFramework,
	TargetArtifacts:      downloadArtifacts,
	TargetAttackTracks:   downloadAttackTracks,
}

var downloadFormatFunc = map[string]func(*metav1.DownloadInfo, registryvulnerabilities.ImageCVEreport) error{
	"pretty-print": prettyPrintDownloadFormat,
	"json":         jsonDownloadFormat,
}

func DownloadSupportCommands() []string {
	commands := []string{}
	for k := range downloadFunc {
		commands = append(commands, k)
	}
	return commands
}

func (ks *Kubescape) Download(downloadInfo *metav1.DownloadInfo) error {
	setPathandFilename(downloadInfo)
	if err := os.MkdirAll(downloadInfo.Path, os.ModePerm); err != nil {
		return err
	}
	if err := downloadArtifact(downloadInfo, downloadFunc); err != nil {
		return err
	}
	return nil
}

func (ks *Kubescape) DownloadImages(downloadInfo *metav1.DownloadInfo) error {

	// load cached config
	getTenantConfig(&downloadInfo.Credentials, "", "", getKubernetesApi())

	// login kubescape SaaS
	ksCloudAPI := getter.GetKSCloudAPIConnector()
	if err := ksCloudAPI.Login(); err != nil {
		return err
	}

	// download image scan results from kubescape SaaS
	adaptors := []registryvulnerabilities.IContainerImageVulnerabilityAdaptor{}
	adaptors = append(adaptors, armosecadaptorv1.NewKSAdaptor(getter.GetKSCloudAPIConnector()))
	vulnerabilitiesList, err := adaptors[0].DownloadImageScanResults()
	if err != nil {
		return err
	}
	logger.L().Success("Downloaded image vulnerabilities successfully")

	// display results in the requested format
	if downloadFormatFunction, ok := downloadFormatFunc[downloadInfo.Format]; ok {
		err := downloadFormatFunction(downloadInfo, vulnerabilitiesList)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("invalid format \"%s\", Supported formats: 'pretty-print'/'json' ", downloadInfo.Format)
	}

	return nil
}

func downloadArtifact(downloadInfo *metav1.DownloadInfo, downloadArtifactFunc map[string]func(*metav1.DownloadInfo) error) error {
	if f, ok := downloadArtifactFunc[downloadInfo.Target]; ok {
		if err := f(downloadInfo); err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("unknown command to download")
}

func setPathandFilename(downloadInfo *metav1.DownloadInfo) {
	if downloadInfo.Path == "" {
		downloadInfo.Path = getter.GetDefaultPath("")
	} else {
		dir, file := filepath.Split(downloadInfo.Path)
		if dir == "" {
			downloadInfo.Path = file
		} else if strings.Contains(file, ".json") {
			downloadInfo.Path = dir
			downloadInfo.FileName = file
		}
	}
}

func downloadArtifacts(downloadInfo *metav1.DownloadInfo) error {
	downloadInfo.FileName = ""
	var artifacts = map[string]func(*metav1.DownloadInfo) error{
		"controls-inputs": downloadConfigInputs,
		"exceptions":      downloadExceptions,
		"framework":       downloadFramework,
		"attack-tracks":   downloadAttackTracks,
	}
	for artifact := range artifacts {
		if err := downloadArtifact(&metav1.DownloadInfo{Target: artifact, Path: downloadInfo.Path, FileName: fmt.Sprintf("%s.json", artifact)}, artifacts); err != nil {
			logger.L().Error("error downloading", helpers.String("artifact", artifact), helpers.Error(err))
		}
	}
	return nil
}

func downloadConfigInputs(downloadInfo *metav1.DownloadInfo) error {
	tenant := getTenantConfig(&downloadInfo.Credentials, "", "", getKubernetesApi())

	controlsInputsGetter := getConfigInputsGetter(downloadInfo.Identifier, tenant.GetAccountID(), nil)
	controlInputs, err := controlsInputsGetter.GetControlsInputs(tenant.GetContextName())
	if err != nil {
		return err
	}
	if downloadInfo.FileName == "" {
		downloadInfo.FileName = fmt.Sprintf("%s.json", downloadInfo.Target)
	}
	if controlInputs == nil {
		return fmt.Errorf("failed to download controlInputs - received an empty objects")
	}
	// save in file
	err = getter.SaveInFile(controlInputs, filepath.Join(downloadInfo.Path, downloadInfo.FileName))
	if err != nil {
		return err
	}
	logger.L().Success("Downloaded", helpers.String("artifact", downloadInfo.Target), helpers.String("path", filepath.Join(downloadInfo.Path, downloadInfo.FileName)))
	return nil
}

func downloadExceptions(downloadInfo *metav1.DownloadInfo) error {
	tenant := getTenantConfig(&downloadInfo.Credentials, "", "", getKubernetesApi())
	exceptionsGetter := getExceptionsGetter("", tenant.GetAccountID(), nil)

	exceptions, err := exceptionsGetter.GetExceptions(tenant.GetContextName())
	if err != nil {
		return err
	}

	if downloadInfo.FileName == "" {
		downloadInfo.FileName = fmt.Sprintf("%s.json", downloadInfo.Target)
	}
	// save in file
	err = getter.SaveInFile(exceptions, filepath.Join(downloadInfo.Path, downloadInfo.FileName))
	if err != nil {
		return err
	}
	logger.L().Success("Downloaded", helpers.String("artifact", downloadInfo.Target), helpers.String("path", filepath.Join(downloadInfo.Path, downloadInfo.FileName)))
	return nil
}

func downloadAttackTracks(downloadInfo *metav1.DownloadInfo) error {
	var err error
	tenant := getTenantConfig(&downloadInfo.Credentials, "", "", getKubernetesApi())

	attackTracksGetter := getAttackTracksGetter("", tenant.GetAccountID(), nil)

	attackTracks, err := attackTracksGetter.GetAttackTracks()
	if err != nil {
		return err
	}

	if downloadInfo.FileName == "" {
		downloadInfo.FileName = fmt.Sprintf("%s.json", downloadInfo.Target)
	}
	// save in file
	err = getter.SaveInFile(attackTracks, filepath.Join(downloadInfo.Path, downloadInfo.FileName))
	if err != nil {
		return err
	}
	logger.L().Success("Downloaded", helpers.String("attack tracks", downloadInfo.Target), helpers.String("path", filepath.Join(downloadInfo.Path, downloadInfo.FileName)))
	return nil

}

func downloadFramework(downloadInfo *metav1.DownloadInfo) error {

	tenant := getTenantConfig(&downloadInfo.Credentials, "", "", getKubernetesApi())

	g := getPolicyGetter(nil, tenant.GetTenantEmail(), true, nil)

	if downloadInfo.Identifier == "" {
		// if framework name not specified - download all frameworks
		frameworks, err := g.GetFrameworks()
		if err != nil {
			return err
		}
		for _, fw := range frameworks {
			downloadTo := filepath.Join(downloadInfo.Path, (strings.ToLower(fw.Name) + ".json"))
			err = getter.SaveInFile(fw, downloadTo)
			if err != nil {
				return err
			}
			logger.L().Success("Downloaded", helpers.String("artifact", downloadInfo.Target), helpers.String("name", fw.Name), helpers.String("path", downloadTo))
		}
		// return fmt.Errorf("missing framework name")
	} else {
		if downloadInfo.FileName == "" {
			downloadInfo.FileName = fmt.Sprintf("%s.json", downloadInfo.Identifier)
		}
		framework, err := g.GetFramework(downloadInfo.Identifier)
		if err != nil {
			return err
		}
		if framework == nil {
			return fmt.Errorf("failed to download framework - received an empty objects")
		}
		downloadTo := filepath.Join(downloadInfo.Path, downloadInfo.FileName)
		err = getter.SaveInFile(framework, downloadTo)
		if err != nil {
			return err
		}
		logger.L().Success("Downloaded", helpers.String("artifact", downloadInfo.Target), helpers.String("name", framework.Name), helpers.String("path", downloadTo))
	}
	return nil
}

func downloadControl(downloadInfo *metav1.DownloadInfo) error {

	tenant := getTenantConfig(&downloadInfo.Credentials, "", "", getKubernetesApi())

	g := getPolicyGetter(nil, tenant.GetTenantEmail(), false, nil)

	if downloadInfo.Identifier == "" {
		// TODO - support
		return fmt.Errorf("missing control ID")
	}
	if downloadInfo.FileName == "" {
		downloadInfo.FileName = fmt.Sprintf("%s.json", downloadInfo.Identifier)
	}
	controls, err := g.GetControl(downloadInfo.Identifier)
	if err != nil {
		return fmt.Errorf("failed to download control id '%s',  %s", downloadInfo.Identifier, err.Error())
	}
	if controls == nil {
		return fmt.Errorf("failed to download control id '%s' - received an empty objects", downloadInfo.Identifier)
	}
	downloadTo := filepath.Join(downloadInfo.Path, downloadInfo.FileName)
	err = getter.SaveInFile(controls, downloadTo)
	if err != nil {
		return err
	}
	logger.L().Success("Downloaded", helpers.String("artifact", downloadInfo.Target), helpers.String("ID", downloadInfo.Identifier), helpers.String("path", downloadTo))
	return nil
}

func jsonDownloadFormat(downloadInfo *metav1.DownloadInfo, vulnReport registryvulnerabilities.ImageCVEreport) error {

	// build results according to JSON format
	vulnMap := reportToJSONmap(vulnReport)

	// create local file
	setPathandFilename(downloadInfo)
	if err := os.MkdirAll(downloadInfo.Path, os.ModePerm); err != nil {
		return err
	}

	// save in file
	err := getter.SaveInFile(vulnMap, filepath.Join(downloadInfo.Path, downloadInfo.FileName))
	if err != nil {
		return err
	}
	logger.L().Success("Saved the image vulnerabilities result successfully")

	return nil
}

// Golang doesn't support marshalling of maps with custom key types (struct in our case)
// Thus, we format the results and build a map with a single key of string type.
func reportToJSONmap(vulnerabilitiesList registryvulnerabilities.ImageCVEreport) map[string][]registryvulnerabilities.ImageVulnerability {

	jsonMap := make(map[string][]registryvulnerabilities.ImageVulnerability, 0)

	for imageReport, vuln := range vulnerabilitiesList {
		jsonMap[imageReport.ImageTag] = append(jsonMap[imageReport.ImageTag], vuln...)
	}

	return jsonMap
}

func prettyPrintDownloadFormat(downloadInfo *metav1.DownloadInfo, vulnerabilitiesList registryvulnerabilities.ImageCVEreport) error {

	imageTable := tablewriter.NewWriter(printer.GetWriter(""))
	imageTable.SetColWidth(25)
	imageTable.SetAutoWrapText(false)
	imageTable.SetHeader([]string{"Cluster", "Namespace", "Workload", "Container Name", "Image ID", "Critical", "High", "Medium", "Low", "Negligible", "Unknown"})
	imageTable.SetHeaderLine(true)
	imageTable.SetRowLine(true)
	imageTable.SetHeaderColor(
		tablewriter.Colors{tablewriter.FgBlueColor},
		tablewriter.Colors{tablewriter.FgBlueColor},
		tablewriter.Colors{tablewriter.FgBlueColor},
		tablewriter.Colors{tablewriter.FgBlueColor},
		tablewriter.Colors{tablewriter.FgBlueColor},
		tablewriter.Colors{tablewriter.FgRedColor},
		tablewriter.Colors{tablewriter.FgHiRedColor},
		tablewriter.Colors{tablewriter.FgYellowColor},
		tablewriter.Colors{tablewriter.FgHiCyanColor},
		tablewriter.Colors{tablewriter.FgCyanColor},
		tablewriter.Colors{tablewriter.FgWhiteColor},
	)
	data := v2.Matrix{}

	imageRows := generateImageRows(vulnerabilitiesList)
	data = append(data, imageRows...)

	imageTable.SetAlignment(tablewriter.ALIGN_LEFT)
	imageTable.AppendBulk(data)
	imageTable.Render()

	return nil
}

func generateImageRows(vulnerabilitiesList registryvulnerabilities.ImageCVEreport) [][]string {
	rows := [][]string{}

	for imageReport, vuln := range vulnerabilitiesList {
		critical, high, medium, low, negligible, unknown := generateServerityCount(vuln)
		imageTag := formatStringToColWidth(imageReport.ImageTag)
		clusterName := formatStringToColWidth(imageReport.Attribute.Cluster)
		namespace := formatStringToColWidth(imageReport.Attribute.Namespace)
		workload := formatStringToColWidth(imageReport.Attribute.Kind + "-" + imageReport.Attribute.Name)
		containerName := formatStringToColWidth(imageReport.Attribute.ContainerName)
		currentRow := []string{clusterName, namespace, workload, containerName, imageTag, critical, high, medium, low, negligible, unknown}
		rows = append(rows, currentRow)
	}

	return rows
}

// The methods provided by "tablewriter" for formatting of text according to the column width don't work in our case.
// They format strings which consists of multiple words. It uses these whitespaces characters for formatting the text.
// However, in our case, we have a string of a single word with large length, which "tablewriter" doesn't autoformat, hence it doesn't fit in table.
// This function splits the string into multiple lines after every N characters and limits the column width to the "colWidth" variable
func formatStringToColWidth(imageTag string) string {
	colWidth := 25
	var newImageTag string = ""

	for pos, value := range imageTag {
		newImageTag = newImageTag + string(value)
		if pos%colWidth == 0 && pos != 0 {
			newImageTag = newImageTag + "\n"
		}
	}
	return newImageTag
}

func generateServerityCount(imageVulns []registryvulnerabilities.ImageVulnerability) (string, string, string, string, string, string) {
	var critical, high, medium, low, negligible, unknown int = 0, 0, 0, 0, 0, 0

	for _, CVE := range imageVulns {
		switch CVE.Severity {
		case "Critical":
			critical++
		case "High":
			high++
		case "Medium":
			medium++
		case "Low":
			low++
		case "Negligible":
			negligible++
		case "Unknown":
			unknown++
		default:
			logger.L().Fatal("unknown severity type in API response")
		}
	}

	return strconv.Itoa(critical), strconv.Itoa(high), strconv.Itoa(medium), strconv.Itoa(low), strconv.Itoa(negligible), strconv.Itoa(unknown)
}
