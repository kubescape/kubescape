package resourcehandler

import (
	"github.com/armosec/k8s-interface/k8sinterface"
	"github.com/armosec/k8s-interface/workloadinterface"
	"github.com/armosec/kubescape/cautils"
	armosecadaptorv1 "github.com/armosec/kubescape/registryadaptors/armosec/v1"
	"github.com/armosec/kubescape/registryadaptors/registryvulnerabilities"
	"github.com/armosec/opa-utils/shared"
)

const (
	ImagevulnerabilitiesObjectGroup   = "image.vulnscan.com"
	ImagevulnerabilitiesObjectVersion = "v1"
	ImagevulnerabilitiesObjectKind    = "ImageVulnerabilities"
)

type RegistryAdaptors struct {
	adaptors []registryvulnerabilities.IContainerImageVulnerabilityAdaptor
}

func NewRegistryAdaptors() (*RegistryAdaptors, error) {
	// list supported adaptors
	registryAdaptors := &RegistryAdaptors{}
	adaptors, err := listAdaptores()
	if err != nil {
		return registryAdaptors, err
	}
	registryAdaptors.adaptors = adaptors
	return registryAdaptors, nil
}

func (registryAdaptors *RegistryAdaptors) collectImagesVulnerabilities(k8sResourcesMap *cautils.K8SResources, allResources map[string]workloadinterface.IMetadata) error {

	// list cluster images
	images := listImagesTags(k8sResourcesMap, allResources)
	imagesIdentifiers := imageTagsToContainerImageIdentifier(images)

	imagesVulnerability := map[string][]registryvulnerabilities.Vulnerability{}
	for i := range registryAdaptors.adaptors { // login and and get vulnerabilities

		if err := registryAdaptors.adaptors[i].Login(); err != nil {
			return err
		}
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

	// save in resources map
	for i := range metaObjs {
		allResources[metaObjs[i].GetID()] = metaObjs[i]
	}
	(*k8sResourcesMap)[k8sinterface.JoinResourceTriplets(ImagevulnerabilitiesObjectGroup, ImagevulnerabilitiesObjectVersion, ImagevulnerabilitiesObjectKind)] = workloadinterface.ListMetaIDs(metaObjs)

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
					if contianers, err := workload.GetContainers(); err == nil {
						for i := range contianers {
							images = append(images, contianers[i].Image)
						}
					}
					if contianers, err := workload.GetInitContainers(); err == nil {
						for i := range contianers {
							images = append(images, contianers[i].Image)
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
func listAdaptores() ([]registryvulnerabilities.IContainerImageVulnerabilityAdaptor, error) {
	customerGUID := " "
	clientID := " "
	accessKey := " "
	registry := "armoui-dev.eudev3.cyberarmorsoft.com"

	adaptors := []registryvulnerabilities.IContainerImageVulnerabilityAdaptor{}
	armosecAdaptor, err := armosecadaptorv1.NewArmoAdaptor(registry, map[string]string{"accountID": customerGUID, "clientID": clientID, "accessKey": accessKey})
	if err != nil {
		return nil, err
	}

	adaptors = append(adaptors, armosecAdaptor)
	return adaptors, nil
}
