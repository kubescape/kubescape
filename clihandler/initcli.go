package clihandler

import (
	"fmt"
	"io/fs"
	"os"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/k8s-interface/k8sinterface"
	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/cautils/getter"
	"github.com/armosec/kubescape/clihandler/cliinterfaces"
	"github.com/armosec/kubescape/hostsensorutils"
	"github.com/armosec/kubescape/opaprocessor"
	"github.com/armosec/kubescape/policyhandler"
	"github.com/armosec/kubescape/resourcehandler"
	"github.com/armosec/kubescape/resultshandling"
	"github.com/armosec/kubescape/resultshandling/printer"
	"github.com/armosec/kubescape/resultshandling/reporter"
	"github.com/armosec/opa-utils/reporthandling"
	"github.com/golang/glog"
)

type componentInterfaces struct {
	clusterConfig   cautils.IClusterConfig
	resourceHandler resourcehandler.IResourceHandler
	report          reporter.IReport
	printerHandler  printer.IPrinter
}

func initHostSensor(scanInfo *cautils.ScanInfo, k8s *k8sinterface.KubernetesApi) {

	hasHostSensorControls := true
	// we need to determined which controls needs host sensor
	if scanInfo.HostSensor.Get() == nil && hasHostSensorControls {
		scanInfo.HostSensor.SetBool(askUserForHostSensor())
	}
	if hostSensorVal := scanInfo.HostSensor.Get(); hostSensorVal != nil && *hostSensorVal {
		hostSensorHandler, err := hostsensorutils.NewHostSensorHandler(k8s)
		if hostSensorHandler != nil {
			defer func(hostSensorHandler *hostsensorutils.HostSensorHandler) {
				if err := hostSensorHandler.TearDown(); err != nil {
					glog.Errorf("failed to tear down host sensor: %v", err)
				}
			}(hostSensorHandler)
		}
		if err != nil {
			glog.Errorf("failed to deploy host sensor: %v", err)
			return
		}
		scanInfo.ExcludedNamespaces = fmt.Sprintf("%s,%s", scanInfo.ExcludedNamespaces, hostSensorHandler.DaemonSet.Namespace)
		data, err := hostSensorHandler.GetKubeletConfigurations()
		if err != nil {
			glog.Errorf("failed to get kubelet configuration from host sensor: %v", err)
		} else {
			glog.Infof("kubelet configurations from host sensor: %v", data)
		}
	} else {
		fmt.Printf("Skipping nodes scanning\n")
	}
}

func getInterfaces(scanInfo *cautils.ScanInfo) componentInterfaces {
	var resourceHandler resourcehandler.IResourceHandler
	var clusterConfig cautils.IClusterConfig
	var reportHandler reporter.IReport
	var scanningTarget string

	if !scanInfo.ScanRunningCluster() {
		k8sinterface.ConnectedToCluster = false
		clusterConfig = cautils.NewEmptyConfig()

		// load fom file
		resourceHandler = resourcehandler.NewFileResourceHandler(scanInfo.InputPatterns)

		// set mock report (do not send report)
		reportHandler = reporter.NewReportMock()
		scanningTarget = "yaml"
	} else {
		k8s := k8sinterface.NewKubernetesApi()
		initHostSensor(scanInfo, k8s)
		resourceHandler = resourcehandler.NewK8sResourceHandler(k8s, getFieldSelector(scanInfo))
		clusterConfig = cautils.ClusterConfigSetup(scanInfo, k8s, getter.GetArmoAPIConnector())

		// setup reporter
		reportHandler = getReporter(scanInfo)
		scanningTarget = "cluster"
	}

	v := cautils.NewIVersionCheckHandler()
	v.CheckLatestVersion(cautils.NewVersionCheckRequest(cautils.BuildNumber, policyIdentifierNames(scanInfo.PolicyIdentifier), "", scanningTarget))

	// setup printer
	printerHandler := printer.GetPrinter(scanInfo.Format)
	printerHandler.SetWriter(scanInfo.Output)

	return componentInterfaces{
		clusterConfig:   clusterConfig,
		resourceHandler: resourceHandler,
		report:          reportHandler,
		printerHandler:  printerHandler,
	}
}
func setPolicyGetter(scanInfo *cautils.ScanInfo, customerGUID string) {
	if len(scanInfo.UseFrom) > 0 {
		//load from file
		scanInfo.PolicyGetter = getter.NewLoadPolicy(scanInfo.UseFrom)
	} else {
		if customerGUID == "" || !scanInfo.FrameworkScan {
			scanInfo.PolicyGetter = getter.NewDownloadReleasedPolicy()
		} else {
			g := getter.GetArmoAPIConnector()
			g.SetCustomerGUID(customerGUID)
			scanInfo.PolicyGetter = g
			if scanInfo.ScanAll {
				frameworks, err := g.ListCustomFrameworks(customerGUID)
				if err != nil {
					glog.Error("failed to get custom frameworks") // handle error
					return
				}
				scanInfo.SetPolicyIdentifiers(frameworks, reporthandling.KindFramework)
			}
		}
	}
}

func ScanCliSetup(scanInfo *cautils.ScanInfo) error {

	interfaces := getInterfaces(scanInfo)

	setPolicyGetter(scanInfo, interfaces.clusterConfig.GetCustomerGUID())

	processNotification := make(chan *cautils.OPASessionObj)
	reportResults := make(chan *cautils.OPASessionObj)

	if err := interfaces.clusterConfig.SetConfig(scanInfo.Account); err != nil {
		fmt.Println(err)
	}

	cautils.ClusterName = interfaces.clusterConfig.GetClusterName()   // TODO - Deprecated
	cautils.CustomerGUID = interfaces.clusterConfig.GetCustomerGUID() // TODO - Deprecated
	interfaces.report.SetClusterName(interfaces.clusterConfig.GetClusterName())
	interfaces.report.SetCustomerGUID(interfaces.clusterConfig.GetCustomerGUID())
	// cli handler setup
	go func() {
		// policy handler setup
		policyHandler := policyhandler.NewPolicyHandler(&processNotification, interfaces.resourceHandler)

		if err := Scan(policyHandler, scanInfo); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}()

	// processor setup - rego run
	go func() {
		opaprocessorObj := opaprocessor.NewOPAProcessorHandler(&processNotification, &reportResults)
		opaprocessorObj.ProcessRulesListenner()
	}()

	resultsHandling := resultshandling.NewResultsHandler(&reportResults, interfaces.report, interfaces.printerHandler)
	score := resultsHandling.HandleResults(scanInfo)

	// print report url
	interfaces.clusterConfig.GenerateURL()

	adjustedFailThreshold := float32(scanInfo.FailThreshold) / 100
	if score < adjustedFailThreshold {
		return fmt.Errorf("Scan score is below threshold")
	}

	return nil
}

func Scan(policyHandler *policyhandler.PolicyHandler, scanInfo *cautils.ScanInfo) error {
	cautils.ScanStartDisplay()
	policyNotification := &reporthandling.PolicyNotification{
		NotificationType: reporthandling.TypeExecPostureScan,
		Rules:            scanInfo.PolicyIdentifier,
		Designators:      armotypes.PortalDesignator{},
	}
	switch policyNotification.NotificationType {
	case reporthandling.TypeExecPostureScan:
		if err := policyHandler.HandleNotificationRequest(policyNotification, scanInfo); err != nil {
			return err
		}

	default:
		return fmt.Errorf("notification type '%s' Unknown", policyNotification.NotificationType)
	}
	return nil
}

func Submit(submitInterfaces cliinterfaces.SubmitInterfaces) error {

	// list resources
	postureReport, err := submitInterfaces.SubmitObjects.SetResourcesReport()
	if err != nil {
		return err
	}

	// report
	if err := submitInterfaces.Reporter.ActionSendReport(&cautils.OPASessionObj{PostureReport: postureReport}); err != nil {
		return err
	}
	fmt.Printf("\nData has been submitted successfully")
	submitInterfaces.ClusterConfig.GenerateURL()

	return nil
}

func askUserForHostSensor() bool {
	if ssss, err := os.Stdin.Stat(); err == nil {
		// fmt.Printf("Found stdin type: %s\n", ssss.Mode().Type())
		if ssss.Mode().Type()&(fs.ModeDevice|fs.ModeCharDevice) > 0 { //has TTY
			fmt.Printf("Would you like to scan K8s nodes? [y/N]. This is required to collect valuable data for certain controls\n")
			fmt.Printf("Use --enable-host-scan flag to suppress this message\n")
			var b []byte = make([]byte, 1)
			if n, err := os.Stdin.Read(b); err == nil {
				if n > 0 && len(b) > 0 && (b[0] == 'y' || b[0] == 'Y') {
					return true
				}
			}
		}
	}
	return false
}
