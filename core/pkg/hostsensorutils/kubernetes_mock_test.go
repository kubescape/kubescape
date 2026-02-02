package hostsensorutils

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/kubescape/k8s-interface/k8sinterface"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	restclient "k8s.io/client-go/rest"
)

type (
	// K8sMockOption configures our mock of a kubernetes client
	K8sMockOption func(*k8sMockOptions)

	// RestURL indexes a proxied HTTP query to the mocked kubernetes API
	RestURL struct {
		Scheme, Name, Port, Path string
	}
)

type (
	// options to configure the mocked behavior

	k8sMockOptions struct {
		k8sNamespaceOptions
		k8sNodeOptions
		k8sResponseWrapperOptions
		dynamicResourceOptions
	}

	k8sNamespaceOptions struct {
		mockNamespaces map[string]v1.Namespace
	}

	k8sNodeOptions struct {
		mockNodes []v1.Node
		mockPods  []v1.Pod
	}

	k8sResponseWrapperOptions struct {
		scheme, name, port, path string
		params                   map[string]string
		mockResponseForURL       map[RestURL][]byte
		mockErrorResponses       map[RestURL]struct{}
	}

	dynamicResourceOptions struct {
		mockNamespaceScope string
		mockResourceSchema schema.GroupVersionResource
		mockResources      map[string]unstructured.Unstructured
	}

	k8sClientMock struct {
		kubernetes.Interface

		corev1 *coreV1Mock
		*k8sMockOptions
	}

	coreV1Mock struct {
		corev1.CoreV1Interface

		namespaces corev1.NamespaceInterface
		nodes      corev1.NodeInterface
		pods       corev1.PodInterface
		*k8sMockOptions
	}

	podMock struct {
		corev1.PodInterface

		watch watch.Interface
		*k8sMockOptions
	}

	nodeMock struct {
		corev1.NodeInterface
		*k8sMockOptions
	}

	namespaceMock struct {
		corev1.NamespaceInterface
		*k8sMockOptions
		mx sync.Mutex
	}

	responseWrapperMock struct {
		restclient.ResponseWrapper
		*k8sMockOptions
		mx sync.Mutex
	}

	dynamicClientMock struct {
		dynamic.Interface
		*k8sMockOptions
	}

	dynamicNSResourceMock struct {
		dynamic.NamespaceableResourceInterface
		*k8sMockOptions
	}

	watchMock struct {
		watch.Interface

		eventChan chan watch.Event
		doneChan  chan struct{}
		wg        sync.WaitGroup
		mx        sync.Mutex

		*k8sMockOptions
	}
)

// NewKubernetesApiMock allows to inject a limited mock for a kubernetes client, covering the interactions carried out by the hostsensor package.
//
// NOTE(fredbi): to achieve full test coverage, the following interfaces need to be added:
// * CoreV1.Namespaces().Delete()
// * AppsV1.DaemonSets()
func NewKubernetesApiMock(opts ...K8sMockOption) *k8sinterface.KubernetesApi {
	return &k8sinterface.KubernetesApi{
		KubernetesClient: newK8sClient(opts...),
		DynamicClient:    newDynamicClient(opts...),
	}
}

func k8sMockWithOptions(opts []K8sMockOption) *k8sMockOptions {
	options := &k8sMockOptions{}
	for _, apply := range opts {
		apply(options)
	}

	return options
}

func WithScheme(scheme string) K8sMockOption {
	return func(o *k8sMockOptions) {
		o.scheme = scheme
	}
}

func WithName(name string) K8sMockOption {
	return func(o *k8sMockOptions) {
		o.name = name
	}
}

func WithPort(port string) K8sMockOption {
	return func(o *k8sMockOptions) {
		o.port = port
	}
}

func WithPath(path string) K8sMockOption {
	return func(o *k8sMockOptions) {
		o.path = path
	}
}

func WithParams(params map[string]string) K8sMockOption {
	return func(o *k8sMockOptions) {
		o.params = params
	}
}

func WithNodes(nodes []v1.Node) K8sMockOption {
	return func(o *k8sMockOptions) {
		o.mockNodes = nodes
	}
}

func WithNode(node v1.Node) K8sMockOption {
	return func(o *k8sMockOptions) {
		o.mockNodes = append(o.mockNodes, node)
	}
}

func WithPods(pods []v1.Pod) K8sMockOption {
	return func(o *k8sMockOptions) {
		o.mockPods = pods
	}
}

func WithPod(pod v1.Pod) K8sMockOption {
	return func(o *k8sMockOptions) {
		o.mockPods = append(o.mockPods, pod)
	}
}

func WithNamespaces(ns []v1.Namespace) K8sMockOption {
	return func(o *k8sMockOptions) {
		if o.mockNamespaces == nil {
			o.mockNamespaces = make(map[string]v1.Namespace, len(ns))
		}

		for _, namespace := range ns {
			o.mockNamespaces[namespace.Name] = namespace
		}
	}
}

func WithNamespace(namespace v1.Namespace) K8sMockOption {
	return func(o *k8sMockOptions) {
		if o.mockNamespaces == nil {
			o.mockNamespaces = make(map[string]v1.Namespace)
		}

		o.mockNamespaces[namespace.Name] = namespace
	}
}

func WithErrorResponse(key RestURL) K8sMockOption {
	return func(o *k8sMockOptions) {
		if o.mockErrorResponses == nil {
			o.mockErrorResponses = make(map[RestURL]struct{})
		}

		o.mockErrorResponses[key] = struct{}{}
	}
}

func WithResponses(responses map[RestURL][]byte) K8sMockOption {
	return func(o *k8sMockOptions) {
		o.mockResponseForURL = responses
	}
}

func WithResponse(at RestURL, resp []byte) K8sMockOption {
	return func(o *k8sMockOptions) {
		if o.mockResponseForURL == nil {
			o.mockResponseForURL = make(map[RestURL][]byte)
		}

		o.mockResponseForURL[at] = resp
	}
}

func WithResourceSchema(resourceSchema schema.GroupVersionResource) K8sMockOption {
	return func(o *k8sMockOptions) {
		o.mockResourceSchema = resourceSchema
	}
}

func WithNamespaceScope(namespace string) K8sMockOption {
	return func(o *k8sMockOptions) {
		o.mockNamespaceScope = namespace
	}
}

func WithResources(resources map[string]unstructured.Unstructured) K8sMockOption {
	return func(o *k8sMockOptions) {
		o.mockResources = resources
	}
}
func WithResource(name string, resource unstructured.Unstructured) K8sMockOption {
	return func(o *k8sMockOptions) {
		if o.mockResources == nil {
			o.mockResources = make(map[string]unstructured.Unstructured)
		}

		o.mockResources[name] = resource
	}
}

func withOptions(full *k8sMockOptions) K8sMockOption {
	return func(o *k8sMockOptions) {
		*o = *full
	}
}

func newK8sClient(opts ...K8sMockOption) *k8sClientMock {
	return &k8sClientMock{
		corev1:         newCoreV1Mock(opts...),
		k8sMockOptions: k8sMockWithOptions(opts),
	}
}

func newDynamicClient(opts ...K8sMockOption) *dynamicClientMock {
	return &dynamicClientMock{
		k8sMockOptions: k8sMockWithOptions(opts),
	}
}

func newNSResourceMock(opts ...K8sMockOption) *dynamicNSResourceMock {
	return &dynamicNSResourceMock{
		k8sMockOptions: k8sMockWithOptions(opts),
	}
}

func newCoreV1Mock(opts ...K8sMockOption) *coreV1Mock {
	return &coreV1Mock{
		namespaces:     newNamespaceMock(opts...),
		nodes:          newNodeMock(opts...),
		pods:           newPodMock(opts...),
		k8sMockOptions: k8sMockWithOptions(opts),
	}
}

func newNamespaceMock(opts ...K8sMockOption) *namespaceMock {
	return &namespaceMock{
		k8sMockOptions: k8sMockWithOptions(opts),
	}
}

func newNodeMock(opts ...K8sMockOption) *nodeMock {
	return &nodeMock{
		k8sMockOptions: k8sMockWithOptions(opts),
	}
}

func newPodMock(opts ...K8sMockOption) *podMock {
	return &podMock{
		watch:          newWatchMock(opts...),
		k8sMockOptions: k8sMockWithOptions(opts),
	}
}

func newResponseWrapperMock(opts ...K8sMockOption) *responseWrapperMock {
	return &responseWrapperMock{
		k8sMockOptions: k8sMockWithOptions(opts),
	}
}

func newWatchMock(opts ...K8sMockOption) *watchMock {
	w := &watchMock{
		eventChan:      make(chan watch.Event),
		doneChan:       make(chan struct{}),
		k8sMockOptions: k8sMockWithOptions(opts),
	}

	w.wg.Add(1)
	go func() {
		defer w.wg.Done()

		for _, toPin := range w.mockPods {
			pod := toPin

			select {
			case <-w.doneChan:
				close(w.eventChan)

				return
			default:
			}

			w.eventChan <- watch.Event{
				Type:   watch.Added,
				Object: &pod,
			}
		}
	}()

	return w
}

func (k *k8sClientMock) CoreV1() corev1.CoreV1Interface {
	return k.corev1
}

func (c *coreV1Mock) Pods(namespace string) corev1.PodInterface {
	return c.pods
}

func (c *coreV1Mock) Namespaces() corev1.NamespaceInterface {
	return c.namespaces
}

func (c *coreV1Mock) Nodes() corev1.NodeInterface {
	return c.nodes
}

func (r *dynamicClientMock) Resource(resourceSchema schema.GroupVersionResource) dynamic.NamespaceableResourceInterface {
	return newNSResourceMock(withOptions(r.k8sMockOptions), WithResourceSchema(resourceSchema))
}

func (n *namespaceMock) Delete(_ context.Context, name string, _ metav1.DeleteOptions) error {
	n.mx.Lock()
	defer n.mx.Unlock()

	if n.mockNamespaces != nil {
		if _, ok := n.mockNamespaces[name]; ok {
			delete(n.mockNamespaces, name)

			return nil
		}
	}

	return fmt.Errorf("namespace not found: %s", name)
}

func (n *namespaceMock) Get(_ context.Context, name string, _ metav1.GetOptions) (*v1.Namespace, error) {
	if namespace, ok := n.mockNamespaces[name]; ok {
		return &namespace, nil
	}

	return nil, fmt.Errorf("namespace not found: %s", name)
}

func (n *nodeMock) List(_ context.Context, _ metav1.ListOptions) (*v1.NodeList, error) {
	nodes := &v1.NodeList{
		TypeMeta: metav1.TypeMeta{
			Kind:       "NodeList",
			APIVersion: "v1",
		},
		Items: n.mockNodes,
	}

	return nodes, nil
}

func (n *podMock) ProxyGet(scheme, name, port, path string, params map[string]string) restclient.ResponseWrapper {
	return newResponseWrapperMock(
		withOptions(n.k8sMockOptions),
		WithScheme(scheme), WithName(name), WithPort(port), WithPath(path),
		WithParams(params),
	)
}

func (n *podMock) Watch(_ context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	return n.watch, nil
}

func (r *responseWrapperMock) DoRaw(_ context.Context) ([]byte, error) {
	r.mx.Lock()
	defer r.mx.Unlock()

	if r.mockErrorResponses != nil {
		if _, ok := r.mockErrorResponses[RestURL{r.scheme, r.name, r.port, r.path}]; ok {
			return nil, errors.New("mock sayz error")
		}
	}
	if r.mockResponseForURL != nil {
		if resp, ok := r.mockResponseForURL[RestURL{r.scheme, r.name, r.port, r.path}]; ok {
			return resp, nil
		}
	}

	return nil, fmt.Errorf("URL not found: %s://%s:%s%s", r.scheme, r.name, r.port, r.path)
}

func (n *dynamicNSResourceMock) Namespace(namespace string) dynamic.ResourceInterface {
	return newNSResourceMock(withOptions(n.k8sMockOptions), WithNamespaceScope(namespace))
}

func (n *dynamicNSResourceMock) Get(_ context.Context, name string, _ metav1.GetOptions, subresources ...string) (*unstructured.Unstructured, error) {
	if n.mockResources != nil {
		if resource, ok := n.mockResources[name]; ok {
			return &resource, nil
		}
	}

	return nil, fmt.Errorf("resource not found: %s", name)
}

func (n *dynamicNSResourceMock) Create(_ context.Context, obj *unstructured.Unstructured, _ metav1.CreateOptions, _ ...string) (*unstructured.Unstructured, error) {
	return obj, nil
}

func (n *dynamicNSResourceMock) Update(_ context.Context, obj *unstructured.Unstructured, _ metav1.UpdateOptions, _ ...string) (*unstructured.Unstructured, error) {
	return obj, nil
}

func (w *watchMock) Stop() {
	w.mx.Lock()
	defer w.mx.Unlock()

	select {
	case _, isOpen := <-w.doneChan:
		if !isOpen {
			return
		}
	default:
	}

	close(w.doneChan)

	w.wg.Wait()
}

func (w *watchMock) ResultChan() <-chan watch.Event {
	return w.eventChan
}
