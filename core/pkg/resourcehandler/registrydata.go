package resourcehandler

import (
	"fmt"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/cautils/getter"
	armosecadaptorv1 "github.com/kubescape/kubescape/v2/core/pkg/registryadaptors/armosec/v1"
	gcpadaptorv1 "github.com/kubescape/kubescape/v2/core/pkg/registryadaptors/gcp/v1"
	"github.com/kubescape/kubescape/v2/core/pkg/registryadaptors/registryvulnerabilities"

	"github.com/kubescape/opa-utils/shared"
)

const (
	ImagevulnerabilitiesObjectGroup   = "armo.vuln.images"
	ImagevulnerabilitiesObjectVersion = "v1"
	ImagevulnerabilitiesObjectKind    = "ImageVulnerabilities"
)

type RegistryAdaptors struct {
	adaptors []registryvulnerabilities.IContainerImageVulnerabilityAdaptor
}

func NewRegistryAdaptors() (*RegistryAdaptors, error) {
	// list supported adaptors
	registryAdaptors := &RegistryAdaptors{}
	adaptors, err := listAdaptors()
	if err != nil {
		return registryAdaptors, err
	}
	registryAdaptors.adaptors = adaptors
	return registryAdaptors, nil
}

func (registryAdaptors *RegistryAdaptors) collectImagesVulnerabilities(k8sResourcesMap *cautils.K8SResources, allResources map[string]workloadinterface.IMetadata, ksResourceMap *cautils.KSResources) error {
	logger.L().Debug("Collecting images vulnerabilities")

	if len(registryAdaptors.adaptors) == 0 {
		return fmt.Errorf("credentials are not configured for any registry adaptor")
	}

	for i := range registryAdaptors.adaptors { // login and and get vulnerabilities
		if err := registryAdaptors.adaptors[i].Login(); err != nil {
			return fmt.Errorf("failed to login, adaptor: '%s', reason: '%s'", registryAdaptors.adaptors[i].DescribeAdaptor(), err.Error())
		}
	}

	// list cluster images
	images := listImagesTags(k8sResourcesMap, allResources)
	imagesIdentifiers := imageTagsToContainerImageIdentifier(images)

	imagesVulnerability := map[string][]registryvulnerabilities.Vulnerability{}
	for i := range registryAdaptors.adaptors { // login and and get vulnerabilities

		vulnerabilities, err := registryAdaptors.adaptors[i].GetImagesVulnerabilities(imagesIdentifiers)
		if err != nil {
			return err
		}
		for j := range vulnerabilities {
			imagesVulnerability[vulnerabilities[j].ImageID.Tag] = vulnerabilities[j].Vulnerabilities
		}
	}

	// convert result to IMetadata object
	metaObjs := vulnerabilitiesToIMetadata(imagesVulnerability)

	if len(metaObjs) == 0 {
		return fmt.Errorf("no vulnerabilities found for any of the images")
	}

	// save in resources map
	for i := range metaObjs {
		allResources[metaObjs[i].GetID()] = metaObjs[i]
	}
	(*ksResourceMap)[k8sinterface.JoinResourceTriplets(ImagevulnerabilitiesObjectGroup, ImagevulnerabilitiesObjectVersion, ImagevulnerabilitiesObjectKind)] = workloadinterface.ListMetaIDs(metaObjs)

	return nil
}

func vulnerabilitiesToIMetadata(vulnerabilities map[string][]registryvulnerabilities.Vulnerability) []workloadinterface.IMetadata {
	objs := []workloadinterface.IMetadata{}
	for i := range vulnerabilities {
		objs = append(objs, vulnerabilityToIMetadata(i, vulnerabilities[i]))
	}
	return objs
}

func vulnerabilityToIMetadata(imageTag string, vulnerabilities []registryvulnerabilities.Vulnerability) workloadinterface.IMetadata {
	obj := map[string]interface{}{}
	metadata := map[string]interface{}{}
	metadata["name"] = imageTag // store image tag as object name
	obj["kind"] = ImagevulnerabilitiesObjectKind
	obj["apiVersion"] = k8sinterface.JoinGroupVersion(ImagevulnerabilitiesObjectGroup, ImagevulnerabilitiesObjectVersion)
	obj["data"] = vulnerabilities
	obj["metadata"] = metadata

	return workloadinterface.NewWorkloadObj(obj)
}

// list all images tags
func listImagesTags(k8sResourcesMap *cautils.K8SResources, allResources map[string]workloadinterface.IMetadata) []string {
	images := []string{}
	for _, resources := range *k8sResourcesMap {
		for j := range resources {
			if resource, ok := allResources[resources[j]]; ok {
				if resource.GetObjectType() == workloadinterface.TypeWorkloadObject {
					workload := workloadinterface.NewWorkloadObj(resource.GetObject())
					if containers, err := workload.GetContainers(); err == nil {
						for i := range containers {
							images = append(images, containers[i].Image)
						}
					}
					if containers, err := workload.GetInitContainers(); err == nil {
						for i := range containers {
							images = append(images, containers[i].Image)
						}
					}
				}
			}
		}
	}

	return shared.SliceStringToUnique(images)
}

func imageTagsToContainerImageIdentifier(images []string) []registryvulnerabilities.ContainerImageIdentifier {
	imagesIdentifiers := make([]registryvulnerabilities.ContainerImageIdentifier, len(images))
	for i := range images {
		imageIdentifier := registryvulnerabilities.ContainerImageIdentifier{
			Tag: images[i],
		}
		// splitted := strings.Split(images[i], "/")
		// if len(splitted) == 1 {
		// 	imageIdentifier.Tag = splitted[0]
		// } else if len(splitted) == 2 {
		// 	imageIdentifier.Registry = splitted[0]
		// 	imageIdentifier.Tag = splitted[1]
		// } else if len(splitted) >= 3 {
		// 	imageIdentifier.Registry = splitted[0]
		// 	imageIdentifier.Repository = strings.Join(splitted[1:len(splitted)-1], "/")
		// 	imageIdentifier.Tag = splitted[len(splitted)-1]
		// }
		imagesIdentifiers[i] = imageIdentifier
	}
	return imagesIdentifiers
}
func listAdaptors() ([]registryvulnerabilities.IContainerImageVulnerabilityAdaptor, error) {

	adaptors := []registryvulnerabilities.IContainerImageVulnerabilityAdaptor{}

	ksCloudAPI := getter.GetKSCloudAPIConnector()
	if ksCloudAPI != nil {
		if ksCloudAPI.GetSecretKey() != "" && ksCloudAPI.GetClientID() != "" && ksCloudAPI.GetAccountID() != "" {
			adaptors = append(adaptors, armosecadaptorv1.NewKSAdaptor(getter.GetKSCloudAPIConnector()))
		}
	}

	gcpCloudAPI := getter.GetGlobalGCPCloudAPIConnector()
	if gcpCloudAPI != nil {
		if gcpCloudAPI.GetCredentialsCheck() {
			adaptors = append(adaptors, gcpadaptorv1.NewGCPAdaptor(getter.GetGlobalGCPCloudAPIConnector()))
		}
	}

	return adaptors, nil
}
