package listener

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/armosec/armoapi-go/armotypes"
	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v3/core/cautils/getter"
	"github.com/kubescape/opa-utils/reporthandling"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/tools/cache"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// RecoverFunc recover function for http requests
func RecoverFunc(w http.ResponseWriter) {
	if err := recover(); err != nil {
		logger.L().Error("", helpers.Error(fmt.Errorf("%v", err)))
		w.WriteHeader(http.StatusInternalServerError)
		bErr, _ := json.Marshal(err)
		w.Write(bErr)
	}
}

func loadExceptions(k8sApi *k8sinterface.KubernetesApi) {
	exceptionCRDs, _ := k8sApi.DynamicClient.Resource(schema.GroupVersionResource{
		Group:    "spdx.softwarecomposition.kubescape.io",
		Version:  "v1alpha1",
		Resource: "exceptions",
	}).List(context.TODO(), metav1.ListOptions{})

	for _, exceptionCRD := range exceptionCRDs.Items {
		data, _ := json.Marshal(exceptionCRD.Object["payload"])
		var exceptions []armotypes.PostureExceptionPolicy
		json.Unmarshal(data, &exceptions)
		getter.SaveInFile(exceptions, getter.GetDefaultPath(fmt.Sprintf("exceptions/%s.json", exceptionCRD.Object["metadata"].(map[string]interface{})["name"])))
	}
}

func loadControlConfigurations(k8sApi *k8sinterface.KubernetesApi) {
	controlConfigurationCRDs, _ := k8sApi.DynamicClient.Resource(schema.GroupVersionResource{
		Group:    "spdx.softwarecomposition.kubescape.io",
		Version:  "v1alpha1",
		Resource: "controlconfigurations",
	}).List(context.TODO(), metav1.ListOptions{})

	for _, controlConfigurationCRD := range controlConfigurationCRDs.Items {
		data, _ := json.Marshal(controlConfigurationCRD.Object["payload"])
		var controlConfiguration armotypes.CustomerConfig
		json.Unmarshal(data, &controlConfiguration)
		getter.SaveInFile(controlConfiguration, getter.GetDefaultPath(fmt.Sprintf("controlconfigurations/%s.json", controlConfigurationCRD.Object["metadata"].(map[string]interface{})["name"])))
	}
}

func loadRules(k8sApi *k8sinterface.KubernetesApi) {
	ruleCRDs, _ := k8sApi.DynamicClient.Resource(schema.GroupVersionResource{
		Group:    "spdx.softwarecomposition.kubescape.io",
		Version:  "v1alpha1",
		Resource: "rules",
	}).List(context.TODO(), metav1.ListOptions{})

	for _, ruleCRD := range ruleCRDs.Items {
		data, _ := json.Marshal(ruleCRD.Object["payload"])
		var rule reporthandling.PolicyRule
		json.Unmarshal(data, &rule)
		getter.SaveInFile(rule, getter.GetDefaultPath(fmt.Sprintf("rules/%s.json", ruleCRD.Object["metadata"].(map[string]interface{})["name"])))
	}
}

func loadControls(k8sApi *k8sinterface.KubernetesApi) {
	controlCRDs, _ := k8sApi.DynamicClient.Resource(schema.GroupVersionResource{
		Group:    "spdx.softwarecomposition.kubescape.io",
		Version:  "v1alpha1",
		Resource: "controls",
	}).List(context.TODO(), metav1.ListOptions{})

	for _, controlCRD := range controlCRDs.Items {
		data, _ := json.Marshal(controlCRD.Object["payload"])
		var control reporthandling.Control
		json.Unmarshal(data, &control)
		getter.SaveInFile(control, getter.GetDefaultPath(fmt.Sprintf("controls/%s.json", controlCRD.Object["metadata"].(map[string]interface{})["name"])))
	}
}

func loadFrameworks(k8sApi *k8sinterface.KubernetesApi) {
	frameworkCRDs, _ := k8sApi.DynamicClient.Resource(schema.GroupVersionResource{
		Group:    "spdx.softwarecomposition.kubescape.io",
		Version:  "v1alpha1",
		Resource: "frameworks",
	}).List(context.TODO(), metav1.ListOptions{})

	for _, frameworkCRD := range frameworkCRDs.Items {
		data, _ := json.Marshal(frameworkCRD.Object["payload"])
		var framework reporthandling.Framework
		json.Unmarshal(data, &framework)
		getter.SaveInFile(framework, getter.GetDefaultPath(fmt.Sprintf("frameworks/%s.json", frameworkCRD.Object["metadata"].(map[string]interface{})["name"])))
	}
}

func exceptionListener(factory dynamicinformer.DynamicSharedInformerFactory) {
	informer := factory.ForResource(schema.GroupVersionResource{
		Group:    "spdx.softwarecomposition.kubescape.io",
		Version:  "v1alpha1",
		Resource: "exceptions",
	}).Informer()

	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			exceptionCRD := obj.(*unstructured.Unstructured)
			data, _ := json.Marshal(exceptionCRD.Object["payload"])
			var exceptions []armotypes.PostureExceptionPolicy
			json.Unmarshal(data, &exceptions)
			getter.SaveInFile(exceptions, getter.GetDefaultPath(fmt.Sprintf("exceptions/%s.json", exceptionCRD.Object["metadata"].(map[string]interface{})["name"])))
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			oldExceptionCRD := oldObj.(*unstructured.Unstructured)
			_ = os.Remove(getter.GetDefaultPath(fmt.Sprintf("exceptions/%s.json", oldExceptionCRD.Object["metadata"].(map[string]interface{})["name"])))
			newExceptionCRD := newObj.(*unstructured.Unstructured)
			data, _ := json.Marshal(newExceptionCRD.Object["payload"])
			var exceptions []armotypes.PostureExceptionPolicy
			json.Unmarshal(data, &exceptions)
			getter.SaveInFile(exceptions, getter.GetDefaultPath(fmt.Sprintf("exceptions/%s.json", newExceptionCRD.Object["metadata"].(map[string]interface{})["name"])))
		},
		DeleteFunc: func(obj interface{}) {
			exceptionCRD := obj.(*unstructured.Unstructured)
			_ = os.Remove(getter.GetDefaultPath(fmt.Sprintf("exceptions/%s.json", exceptionCRD.Object["metadata"].(map[string]interface{})["name"])))
		},
	})

	go informer.Run(make(<-chan struct{}))
}

func controlConfigurationListener(factory dynamicinformer.DynamicSharedInformerFactory) {
	informer := factory.ForResource(schema.GroupVersionResource{
		Group:    "spdx.softwarecomposition.kubescape.io",
		Version:  "v1alpha1",
		Resource: "controlconfigurations",
	}).Informer()

	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			controlConfigurationCRD := obj.(*unstructured.Unstructured)
			data, _ := json.Marshal(controlConfigurationCRD.Object["payload"])
			var controlConfiguration armotypes.CustomerConfig
			json.Unmarshal(data, &controlConfiguration)
			getter.SaveInFile(controlConfiguration, getter.GetDefaultPath(fmt.Sprintf("controlconfigurations/%s.json", controlConfigurationCRD.Object["metadata"].(map[string]interface{})["name"])))
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			oldControlConfigurationCRD := oldObj.(*unstructured.Unstructured)
			_ = os.Remove(getter.GetDefaultPath(fmt.Sprintf("controlconfigurations/%s.json", oldControlConfigurationCRD.Object["metadata"].(map[string]interface{})["name"])))
			newControlConfigurationCRD := newObj.(*unstructured.Unstructured)
			data, _ := json.Marshal(newControlConfigurationCRD.Object["payload"])
			var controlConfiguration armotypes.CustomerConfig
			json.Unmarshal(data, &controlConfiguration)
			getter.SaveInFile(controlConfiguration, getter.GetDefaultPath(fmt.Sprintf("controlconfigurations/%s.json", newControlConfigurationCRD.Object["metadata"].(map[string]interface{})["name"])))
		},
		DeleteFunc: func(obj interface{}) {
			controlConfigurationCRD := obj.(*unstructured.Unstructured)
			_ = os.Remove(getter.GetDefaultPath(fmt.Sprintf("controlconfigurations/%s.json", controlConfigurationCRD.Object["metadata"].(map[string]interface{})["name"])))
		},
	})

	go informer.Run(make(<-chan struct{}))
}

func ruleListener(factory dynamicinformer.DynamicSharedInformerFactory) {
	informer := factory.ForResource(schema.GroupVersionResource{
		Group:    "spdx.softwarecomposition.kubescape.io",
		Version:  "v1alpha1",
		Resource: "rules",
	}).Informer()

	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			ruleCRD := obj.(*unstructured.Unstructured)
			data, _ := json.Marshal(ruleCRD.Object["payload"])
			var rule reporthandling.PolicyRule
			json.Unmarshal(data, &rule)
			getter.SaveInFile(rule, getter.GetDefaultPath(fmt.Sprintf("rules/%s.json", ruleCRD.Object["metadata"].(map[string]interface{})["name"])))
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			oldRuleCRD := oldObj.(*unstructured.Unstructured)
			_ = os.Remove(getter.GetDefaultPath(fmt.Sprintf("rules/%s.json", oldRuleCRD.Object["metadata"].(map[string]interface{})["name"])))
			newRuleCRD := newObj.(*unstructured.Unstructured)
			data, _ := json.Marshal(newRuleCRD.Object["payload"])
			var rule reporthandling.PolicyRule
			json.Unmarshal(data, &rule)
			getter.SaveInFile(rule, getter.GetDefaultPath(fmt.Sprintf("rules/%s.json", newRuleCRD.Object["metadata"].(map[string]interface{})["name"])))
		},
		DeleteFunc: func(obj interface{}) {
			ruleCRD := obj.(*unstructured.Unstructured)
			_ = os.Remove(getter.GetDefaultPath(fmt.Sprintf("rules/%s.json", ruleCRD.Object["metadata"].(map[string]interface{})["name"])))
		},
	})

	go informer.Run(make(<-chan struct{}))
}

func controlListener(factory dynamicinformer.DynamicSharedInformerFactory) {
	informer := factory.ForResource(schema.GroupVersionResource{
		Group:    "spdx.softwarecomposition.kubescape.io",
		Version:  "v1alpha1",
		Resource: "controls",
	}).Informer()

	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			controlCRD := obj.(*unstructured.Unstructured)
			data, _ := json.Marshal(controlCRD.Object["payload"])
			var control reporthandling.Control
			json.Unmarshal(data, &control)
			getter.SaveInFile(control, getter.GetDefaultPath(fmt.Sprintf("controls/%s.json", controlCRD.Object["metadata"].(map[string]interface{})["name"])))
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			oldControlCRD := oldObj.(*unstructured.Unstructured)
			_ = os.Remove(getter.GetDefaultPath(fmt.Sprintf("controls/%s.json", oldControlCRD.Object["metadata"].(map[string]interface{})["name"])))
			newControlCRD := newObj.(*unstructured.Unstructured)
			data, _ := json.Marshal(newControlCRD.Object["payload"])
			var control reporthandling.Control
			json.Unmarshal(data, &control)
			getter.SaveInFile(control, getter.GetDefaultPath(fmt.Sprintf("controls/%s.json", newControlCRD.Object["metadata"].(map[string]interface{})["name"])))
		},
		DeleteFunc: func(obj interface{}) {
			controlCRD := obj.(*unstructured.Unstructured)
			_ = os.Remove(getter.GetDefaultPath(fmt.Sprintf("controls/%s.json", controlCRD.Object["metadata"].(map[string]interface{})["name"])))
		},
	})

	go informer.Run(make(<-chan struct{}))
}

func frameworkListener(factory dynamicinformer.DynamicSharedInformerFactory) {
	informer := factory.ForResource(schema.GroupVersionResource{
		Group:    "spdx.softwarecomposition.kubescape.io",
		Version:  "v1alpha1",
		Resource: "frameworks",
	}).Informer()

	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			frameworkCRD := obj.(*unstructured.Unstructured)
			data, _ := json.Marshal(frameworkCRD.Object["payload"])
			var framework reporthandling.Framework
			json.Unmarshal(data, &framework)
			getter.SaveInFile(framework, getter.GetDefaultPath(fmt.Sprintf("frameworks/%s.json", frameworkCRD.Object["metadata"].(map[string]interface{})["name"])))
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			oldFrameworkCRD := oldObj.(*unstructured.Unstructured)
			_ = os.Remove(getter.GetDefaultPath(fmt.Sprintf("frameworks/%s.json", oldFrameworkCRD.Object["metadata"].(map[string]interface{})["name"])))
			newFrameworkCRD := newObj.(*unstructured.Unstructured)
			data, _ := json.Marshal(newFrameworkCRD.Object["payload"])
			var framework reporthandling.Framework
			json.Unmarshal(data, &framework)
			getter.SaveInFile(framework, getter.GetDefaultPath(fmt.Sprintf("frameworks/%s.json", newFrameworkCRD.Object["metadata"].(map[string]interface{})["name"])))
		},
		DeleteFunc: func(obj interface{}) {
			frameworkCRD := obj.(*unstructured.Unstructured)
			_ = os.Remove(getter.GetDefaultPath(fmt.Sprintf("frameworks/%s.json", frameworkCRD.Object["metadata"].(map[string]interface{})["name"])))
		},
	})

	go informer.Run(make(<-chan struct{}))
}
