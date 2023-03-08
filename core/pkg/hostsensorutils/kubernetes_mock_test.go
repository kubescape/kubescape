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

func mockNode1() v1.Node {
	return v1.Node{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Node",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "node1",
		},
		// TODO: fill in some mock data
	}
}

func mockPod1() v1.Pod {
	return v1.Pod{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "pod1",
		},
		Status: v1.PodStatus{
			Phase: v1.PodRunning,
			ContainerStatuses: []v1.ContainerStatus{
				{
					Name:  "container1",
					Ready: true,
				},
			},
		},
	}
}

func mockPod2() v1.Pod {
	return v1.Pod{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "pod2",
		},
		Status: v1.PodStatus{
			Phase: v1.PodRunning,
			ContainerStatuses: []v1.ContainerStatus{
				{
					Name:  "container2",
					Ready: true,
				},
			},
		},
	}
}

func mockResponsesNoCloudProvider() map[RestURL][]byte {
	responses := mockResponses()
	responses[RestURL{"http", "pod1", "7888", "/cloudProviderInfo"}] = []byte("{}\n")
	responses[RestURL{"http", "pod2", "7888", "/cloudProviderInfo"}] = []byte("{}\n")

	return responses
}

// mockResponses test scenario (values retrieved from a real minikube cluster)
func mockResponses() map[RestURL][]byte {
	return map[RestURL][]byte{
		{"http", "pod1", "7888", "/version"}:                []byte(`"v1.0.45"`),
		{"http", "pod2", "7888", "/version"}:                []byte(`"v1.0.45"`),
		{"http", "pod1", "7888", "/kubeletConfigurations"}:  []byte("apiVersion: kubelet.config.k8s.io/v1beta1\nauthentication:\n  anonymous:\n    enabled: false\n  webhook:\n    cacheTTL: 0s\n    enabled: true\n  x509:\n    clientCAFile: /var/lib/minikube/certs/ca.crt\nauthorization:\n  mode: Webhook\n  webhook:\n    cacheAuthorizedTTL: 0s\n    cacheUnauthorizedTTL: 0s\ncgroupDriver: systemd\nclusterDNS:\n- 10.96.0.10\nclusterDomain: cluster.local\ncpuManagerReconcilePeriod: 0s\nevictionHard:\n  imagefs.available: 0%\n  nodefs.available: 0%\n  nodefs.inodesFree: 0%\nevictionPressureTransitionPeriod: 0s\nfailSwapOn: false\nfileCheckFrequency: 0s\nhealthzBindAddress: 127.0.0.1\nhealthzPort: 10248\nhttpCheckFrequency: 0s\nimageGCHighThresholdPercent: 100\nimageMinimumGCAge: 0s\nkind: KubeletConfiguration\nlogging: {}\nmemorySwap: {}\nnodeStatusReportFrequency: 0s\nnodeStatusUpdateFrequency: 0s\nresolvConf: /run/systemd/resolve/resolv.conf\nrotateCertificates: true\nruntimeRequestTimeout: 0s\nshutdownGracePeriod: 0s\nshutdownGracePeriodCriticalPods: 0s\nstaticPodPath: /etc/kubernetes/manifests\nstreamingConnectionIdleTimeout: 0s\nsyncFrequency: 0s\nvolumeStatsAggPeriod: 0s\n"),
		{"http", "pod2", "7888", "/kubeletConfigurations"}:  []byte("apiVersion: kubelet.config.k8s.io/v1beta1\nauthentication:\n  anonymous:\n    enabled: false\n  webhook:\n    cacheTTL: 0s\n    enabled: true\n  x509:\n    clientCAFile: /var/lib/minikube/certs/ca.crt\nauthorization:\n  mode: Webhook\n  webhook:\n    cacheAuthorizedTTL: 0s\n    cacheUnauthorizedTTL: 0s\ncgroupDriver: systemd\nclusterDNS:\n- 10.96.0.10\nclusterDomain: cluster.local\ncpuManagerReconcilePeriod: 0s\nevictionHard:\n  imagefs.available: 0%\n  nodefs.available: 0%\n  nodefs.inodesFree: 0%\nevictionPressureTransitionPeriod: 0s\nfailSwapOn: false\nfileCheckFrequency: 0s\nhealthzBindAddress: 127.0.0.1\nhealthzPort: 10248\nhttpCheckFrequency: 0s\nimageGCHighThresholdPercent: 100\nimageMinimumGCAge: 0s\nkind: KubeletConfiguration\nlogging: {}\nmemorySwap: {}\nnodeStatusReportFrequency: 0s\nnodeStatusUpdateFrequency: 0s\nresolvConf: /run/systemd/resolve/resolv.conf\nrotateCertificates: true\nruntimeRequestTimeout: 0s\nshutdownGracePeriod: 0s\nshutdownGracePeriodCriticalPods: 0s\nstaticPodPath: /etc/kubernetes/manifests\nstreamingConnectionIdleTimeout: 0s\nsyncFrequency: 0s\nvolumeStatsAggPeriod: 0s\n"),
		{"http", "pod1", "7888", "/kubeletCommandLine"}:     []byte("/var/lib/minikube/binaries/v1.22.3/kubelet --bootstrap-kubeconfig=/etc/kubernetes/bootstrap-kubelet.conf --config=/var/lib/kubelet/config.yaml --container-runtime=docker --hostname-override=minikube --kubeconfig=/etc/kubernetes/kubelet.conf --node-ip=192.168.59.101 "),
		{"http", "pod2", "7888", "/kubeletCommandLine"}:     []byte("/var/lib/minikube/binaries/v1.22.3/kubelet --bootstrap-kubeconfig=/etc/kubernetes/bootstrap-kubelet.conf --config=/var/lib/kubelet/config.yaml --container-runtime=docker --hostname-override=minikube --kubeconfig=/etc/kubernetes/kubelet.conf --node-ip=192.168.59.101 "),
		{"http", "pod1", "7888", "/osRelease"}:              []byte("NAME=Buildroot\nVERSION=2021.02.4-dirty\nID=buildroot\nVERSION_ID=2021.02.4\nPRETTY_NAME=\"Buildroot 2021.02.4\"\n"),
		{"http", "pod2", "7888", "/osRelease"}:              []byte("NAME=Buildroot\nVERSION=2021.02.4-dirty\nID=buildroot\nVERSION_ID=2021.02.4\nPRETTY_NAME=\"Buildroot 2021.02.4\"\n"),
		{"http", "pod1", "7888", "/kernelVersion"}:          []byte("Linux version 4.19.202 (jenkins@debian10-agent-1) (gcc version 9.4.0 (Buildroot 2021.02.4-dirty)) #1 SMP Wed Oct 27 22:52:27 UTC 2021\n"),
		{"http", "pod2", "7888", "/kernelVersion"}:          []byte("Linux version 4.19.202 (jenkins@debian10-agent-1) (gcc version 9.4.0 (Buildroot 2021.02.4-dirty)) #1 SMP Wed Oct 27 22:52:27 UTC 2021\n"),
		{"http", "pod1", "7888", "/linuxSecurityHardening"}: []byte("{\"appArmor\":\"unloaded\",\"seLinux\":\"not found\"}\n"),
		{"http", "pod2", "7888", "/linuxSecurityHardening"}: []byte("{\"appArmor\":\"unloaded\",\"seLinux\":\"not found\"}\n"),
		{"http", "pod1", "7888", "/openedPorts"}:            []byte("{\"tcpPorts\":[{\"Transport\":\"\",\"LocalAddress\":\"::\",\"LocalPort\":7888,\"RemoteAddress\":\"::\",\"RemotePort\":0,\"PID\":0,\"Name\":\"\"}],\"udpPorts\":[],\"icmpPorts\":[]}\n"),
		{"http", "pod2", "7888", "/openedPorts"}:            []byte("{\"tcpPorts\":[{\"Transport\":\"\",\"LocalAddress\":\"::\",\"LocalPort\":7888,\"RemoteAddress\":\"::\",\"RemotePort\":0,\"PID\":0,\"Name\":\"\"}],\"udpPorts\":[],\"icmpPorts\":[]}\n"),
		{"http", "pod1", "7888", "/LinuxKernelVariables"}:   []byte("[{\"key\":\"acct\",\"value\":\"4\\t2\\t30\\n\",\"source\":\"/proc/sys/kernel/acct\"},{\"key\":\"acpi_video_flags\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/acpi_video_flags\"},{\"key\":\"auto_msgmni\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/auto_msgmni\"},{\"key\":\"bootloader_type\",\"value\":\"48\\n\",\"source\":\"/proc/sys/kernel/bootloader_type\"},{\"key\":\"bootloader_version\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/bootloader_version\"},{\"key\":\"cad_pid\",\"value\":\"1\\n\",\"source\":\"/proc/sys/kernel/cad_pid\"},{\"key\":\"cap_last_cap\",\"value\":\"37\\n\",\"source\":\"/proc/sys/kernel/cap_last_cap\"},{\"key\":\"core_pattern\",\"value\":\"core\\n\",\"source\":\"/proc/sys/kernel/core_pattern\"},{\"key\":\"core_pipe_limit\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/core_pipe_limit\"},{\"key\":\"core_uses_pid\",\"value\":\"1\\n\",\"source\":\"/proc/sys/kernel/core_uses_pid\"},{\"key\":\"ctrl-alt-del\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/ctrl-alt-del\"},{\"key\":\"dmesg_restrict\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/dmesg_restrict\"},{\"key\":\"domainname\",\"value\":\"(none)\\n\",\"source\":\"/proc/sys/kernel/domainname\"},{\"key\":\"ftrace_dump_on_oops\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/ftrace_dump_on_oops\"},{\"key\":\"ftrace_enabled\",\"value\":\"1\\n\",\"source\":\"/proc/sys/kernel/ftrace_enabled\"},{\"key\":\"hostname\",\"value\":\"host-scanner-kwcqd\\n\",\"source\":\"/proc/sys/kernel/hostname\"},{\"key\":\"hotplug\",\"value\":\"/sbin/hotplug\\n\",\"source\":\"/proc/sys/kernel/hotplug\"},{\"key\":\"io_delay_type\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/io_delay_type\"},{\"key\":\"kexec_load_disabled\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/kexec_load_disabled\"},{\"key\":\"gc_delay\",\"value\":\"300\\n\",\"source\":\"/proc/sys/kernel/keys/gc_delay\"},{\"key\":\"maxbytes\",\"value\":\"20000\\n\",\"source\":\"/proc/sys/kernel/keys/maxbytes\"},{\"key\":\"maxkeys\",\"value\":\"200\\n\",\"source\":\"/proc/sys/kernel/keys/maxkeys\"},{\"key\":\"root_maxbytes\",\"value\":\"25000000\\n\",\"source\":\"/proc/sys/kernel/keys/root_maxbytes\"},{\"key\":\"root_maxkeys\",\"value\":\"1000000\\n\",\"source\":\"/proc/sys/kernel/keys/root_maxkeys\"},{\"key\":\"kptr_restrict\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/kptr_restrict\"},{\"key\":\"max_lock_depth\",\"value\":\"1024\\n\",\"source\":\"/proc/sys/kernel/max_lock_depth\"},{\"key\":\"modprobe\",\"value\":\"/sbin/modprobe\\n\",\"source\":\"/proc/sys/kernel/modprobe\"},{\"key\":\"modules_disabled\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/modules_disabled\"},{\"key\":\"msgmax\",\"value\":\"8192\\n\",\"source\":\"/proc/sys/kernel/msgmax\"},{\"key\":\"msgmnb\",\"value\":\"16384\\n\",\"source\":\"/proc/sys/kernel/msgmnb\"},{\"key\":\"msgmni\",\"value\":\"32000\\n\",\"source\":\"/proc/sys/kernel/msgmni\"},{\"key\":\"ngroups_max\",\"value\":\"65536\\n\",\"source\":\"/proc/sys/kernel/ngroups_max\"},{\"key\":\"osrelease\",\"value\":\"4.19.202\\n\",\"source\":\"/proc/sys/kernel/osrelease\"},{\"key\":\"ostype\",\"value\":\"Linux\\n\",\"source\":\"/proc/sys/kernel/ostype\"},{\"key\":\"overflowgid\",\"value\":\"65534\\n\",\"source\":\"/proc/sys/kernel/overflowgid\"},{\"key\":\"overflowuid\",\"value\":\"65534\\n\",\"source\":\"/proc/sys/kernel/overflowuid\"},{\"key\":\"panic\",\"value\":\"10\\n\",\"source\":\"/proc/sys/kernel/panic\"},{\"key\":\"panic_on_io_nmi\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/panic_on_io_nmi\"},{\"key\":\"panic_on_oops\",\"value\":\"1\\n\",\"source\":\"/proc/sys/kernel/panic_on_oops\"},{\"key\":\"panic_on_rcu_stall\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/panic_on_rcu_stall\"},{\"key\":\"panic_on_stackoverflow\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/panic_on_stackoverflow\"},{\"key\":\"panic_on_unrecovered_nmi\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/panic_on_unrecovered_nmi\"},{\"key\":\"panic_on_warn\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/panic_on_warn\"},{\"key\":\"perf_cpu_time_max_percent\",\"value\":\"25\\n\",\"source\":\"/proc/sys/kernel/perf_cpu_time_max_percent\"},{\"key\":\"perf_event_max_contexts_per_stack\",\"value\":\"8\\n\",\"source\":\"/proc/sys/kernel/perf_event_max_contexts_per_stack\"},{\"key\":\"perf_event_max_sample_rate\",\"value\":\"100000\\n\",\"source\":\"/proc/sys/kernel/perf_event_max_sample_rate\"},{\"key\":\"perf_event_max_stack\",\"value\":\"127\\n\",\"source\":\"/proc/sys/kernel/perf_event_max_stack\"},{\"key\":\"perf_event_mlock_kb\",\"value\":\"516\\n\",\"source\":\"/proc/sys/kernel/perf_event_mlock_kb\"},{\"key\":\"perf_event_paranoid\",\"value\":\"2\\n\",\"source\":\"/proc/sys/kernel/perf_event_paranoid\"},{\"key\":\"pid_max\",\"value\":\"4194304\\n\",\"source\":\"/proc/sys/kernel/pid_max\"},{\"key\":\"poweroff_cmd\",\"value\":\"/sbin/poweroff\\n\",\"source\":\"/proc/sys/kernel/poweroff_cmd\"},{\"key\":\"print-fatal-signals\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/print-fatal-signals\"},{\"key\":\"printk\",\"value\":\"3\\t4\\t1\\t7\\n\",\"source\":\"/proc/sys/kernel/printk\"},{\"key\":\"printk_delay\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/printk_delay\"},{\"key\":\"printk_devkmsg\",\"value\":\"on\\n\",\"source\":\"/proc/sys/kernel/printk_devkmsg\"},{\"key\":\"printk_ratelimit\",\"value\":\"5\\n\",\"source\":\"/proc/sys/kernel/printk_ratelimit\"},{\"key\":\"printk_ratelimit_burst\",\"value\":\"10\\n\",\"source\":\"/proc/sys/kernel/printk_ratelimit_burst\"},{\"key\":\"max\",\"value\":\"4096\\n\",\"source\":\"/proc/sys/kernel/pty/max\"},{\"key\":\"nr\",\"value\":\"1\\n\",\"source\":\"/proc/sys/kernel/pty/nr\"},{\"key\":\"reserve\",\"value\":\"1024\\n\",\"source\":\"/proc/sys/kernel/pty/reserve\"},{\"key\":\"boot_id\",\"value\":\"7fbec4c7-1230-422f-95ce-5528cd1c54c4\\n\",\"source\":\"/proc/sys/kernel/random/boot_id\"},{\"key\":\"entropy_avail\",\"value\":\"3794\\n\",\"source\":\"/proc/sys/kernel/random/entropy_avail\"},{\"key\":\"poolsize\",\"value\":\"4096\\n\",\"source\":\"/proc/sys/kernel/random/poolsize\"},{\"key\":\"read_wakeup_threshold\",\"value\":\"64\\n\",\"source\":\"/proc/sys/kernel/random/read_wakeup_threshold\"},{\"key\":\"urandom_min_reseed_secs\",\"value\":\"60\\n\",\"source\":\"/proc/sys/kernel/random/urandom_min_reseed_secs\"},{\"key\":\"uuid\",\"value\":\"2889254b-e006-4e53-86b0-3155dc2361b9\\n\",\"source\":\"/proc/sys/kernel/random/uuid\"},{\"key\":\"write_wakeup_threshold\",\"value\":\"896\\n\",\"source\":\"/proc/sys/kernel/random/write_wakeup_threshold\"},{\"key\":\"randomize_va_space\",\"value\":\"2\\n\",\"source\":\"/proc/sys/kernel/randomize_va_space\"},{\"key\":\"real-root-dev\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/real-root-dev\"},{\"key\":\"sched_cfs_bandwidth_slice_us\",\"value\":\"5000\\n\",\"source\":\"/proc/sys/kernel/sched_cfs_bandwidth_slice_us\"},{\"key\":\"sched_child_runs_first\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/sched_child_runs_first\"},{\"key\":\"sched_rr_timeslice_ms\",\"value\":\"100\\n\",\"source\":\"/proc/sys/kernel/sched_rr_timeslice_ms\"},{\"key\":\"sched_rt_period_us\",\"value\":\"1000000\\n\",\"source\":\"/proc/sys/kernel/sched_rt_period_us\"},{\"key\":\"sched_rt_runtime_us\",\"value\":\"950000\\n\",\"source\":\"/proc/sys/kernel/sched_rt_runtime_us\"},{\"key\":\"actions_avail\",\"value\":\"kill_process kill_thread trap errno trace log allow\\n\",\"source\":\"/proc/sys/kernel/seccomp/actions_avail\"},{\"key\":\"actions_logged\",\"value\":\"kill_process kill_thread trap errno trace log\\n\",\"source\":\"/proc/sys/kernel/seccomp/actions_logged\"},{\"key\":\"sem\",\"value\":\"32000\\t1024000000\\t500\\t32000\\n\",\"source\":\"/proc/sys/kernel/sem\"},{\"key\":\"sg-big-buff\",\"value\":\"32768\\n\",\"source\":\"/proc/sys/kernel/sg-big-buff\"},{\"key\":\"shm_rmid_forced\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/shm_rmid_forced\"},{\"key\":\"shmall\",\"value\":\"18446744073692774399\\n\",\"source\":\"/proc/sys/kernel/shmall\"},{\"key\":\"shmmax\",\"value\":\"18446744073692774399\\n\",\"source\":\"/proc/sys/kernel/shmmax\"},{\"key\":\"shmmni\",\"value\":\"4096\\n\",\"source\":\"/proc/sys/kernel/shmmni\"},{\"key\":\"sysctl_writes_strict\",\"value\":\"1\\n\",\"source\":\"/proc/sys/kernel/sysctl_writes_strict\"},{\"key\":\"sysrq\",\"value\":\"16\\n\",\"source\":\"/proc/sys/kernel/sysrq\"},{\"key\":\"tainted\",\"value\":\"4096\\n\",\"source\":\"/proc/sys/kernel/tainted\"},{\"key\":\"threads-max\",\"value\":\"62033\\n\",\"source\":\"/proc/sys/kernel/threads-max\"},{\"key\":\"timer_migration\",\"value\":\"1\\n\",\"source\":\"/proc/sys/kernel/timer_migration\"},{\"key\":\"traceoff_on_warning\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/traceoff_on_warning\"},{\"key\":\"tracepoint_printk\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/tracepoint_printk\"},{\"key\":\"unknown_nmi_panic\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/unknown_nmi_panic\"},{\"key\":\"unprivileged_bpf_disabled\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/unprivileged_bpf_disabled\"},{\"key\":\"bset\",\"value\":\"4294967295\\t63\\n\",\"source\":\"/proc/sys/kernel/usermodehelper/bset\"},{\"key\":\"inheritable\",\"value\":\"4294967295\\t63\\n\",\"source\":\"/proc/sys/kernel/usermodehelper/inheritable\"},{\"key\":\"version\",\"value\":\"#1 SMP Wed Oct 27 22:52:27 UTC 2021\\n\",\"source\":\"/proc/sys/kernel/version\"}]\n"),
		{"http", "pod2", "7888", "/LinuxKernelVariables"}:   []byte("[{\"key\":\"acct\",\"value\":\"4\\t2\\t30\\n\",\"source\":\"/proc/sys/kernel/acct\"},{\"key\":\"acpi_video_flags\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/acpi_video_flags\"},{\"key\":\"auto_msgmni\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/auto_msgmni\"},{\"key\":\"bootloader_type\",\"value\":\"48\\n\",\"source\":\"/proc/sys/kernel/bootloader_type\"},{\"key\":\"bootloader_version\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/bootloader_version\"},{\"key\":\"cad_pid\",\"value\":\"1\\n\",\"source\":\"/proc/sys/kernel/cad_pid\"},{\"key\":\"cap_last_cap\",\"value\":\"37\\n\",\"source\":\"/proc/sys/kernel/cap_last_cap\"},{\"key\":\"core_pattern\",\"value\":\"core\\n\",\"source\":\"/proc/sys/kernel/core_pattern\"},{\"key\":\"core_pipe_limit\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/core_pipe_limit\"},{\"key\":\"core_uses_pid\",\"value\":\"1\\n\",\"source\":\"/proc/sys/kernel/core_uses_pid\"},{\"key\":\"ctrl-alt-del\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/ctrl-alt-del\"},{\"key\":\"dmesg_restrict\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/dmesg_restrict\"},{\"key\":\"domainname\",\"value\":\"(none)\\n\",\"source\":\"/proc/sys/kernel/domainname\"},{\"key\":\"ftrace_dump_on_oops\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/ftrace_dump_on_oops\"},{\"key\":\"ftrace_enabled\",\"value\":\"1\\n\",\"source\":\"/proc/sys/kernel/ftrace_enabled\"},{\"key\":\"hostname\",\"value\":\"host-scanner-kwcqd\\n\",\"source\":\"/proc/sys/kernel/hostname\"},{\"key\":\"hotplug\",\"value\":\"/sbin/hotplug\\n\",\"source\":\"/proc/sys/kernel/hotplug\"},{\"key\":\"io_delay_type\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/io_delay_type\"},{\"key\":\"kexec_load_disabled\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/kexec_load_disabled\"},{\"key\":\"gc_delay\",\"value\":\"300\\n\",\"source\":\"/proc/sys/kernel/keys/gc_delay\"},{\"key\":\"maxbytes\",\"value\":\"20000\\n\",\"source\":\"/proc/sys/kernel/keys/maxbytes\"},{\"key\":\"maxkeys\",\"value\":\"200\\n\",\"source\":\"/proc/sys/kernel/keys/maxkeys\"},{\"key\":\"root_maxbytes\",\"value\":\"25000000\\n\",\"source\":\"/proc/sys/kernel/keys/root_maxbytes\"},{\"key\":\"root_maxkeys\",\"value\":\"1000000\\n\",\"source\":\"/proc/sys/kernel/keys/root_maxkeys\"},{\"key\":\"kptr_restrict\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/kptr_restrict\"},{\"key\":\"max_lock_depth\",\"value\":\"1024\\n\",\"source\":\"/proc/sys/kernel/max_lock_depth\"},{\"key\":\"modprobe\",\"value\":\"/sbin/modprobe\\n\",\"source\":\"/proc/sys/kernel/modprobe\"},{\"key\":\"modules_disabled\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/modules_disabled\"},{\"key\":\"msgmax\",\"value\":\"8192\\n\",\"source\":\"/proc/sys/kernel/msgmax\"},{\"key\":\"msgmnb\",\"value\":\"16384\\n\",\"source\":\"/proc/sys/kernel/msgmnb\"},{\"key\":\"msgmni\",\"value\":\"32000\\n\",\"source\":\"/proc/sys/kernel/msgmni\"},{\"key\":\"ngroups_max\",\"value\":\"65536\\n\",\"source\":\"/proc/sys/kernel/ngroups_max\"},{\"key\":\"osrelease\",\"value\":\"4.19.202\\n\",\"source\":\"/proc/sys/kernel/osrelease\"},{\"key\":\"ostype\",\"value\":\"Linux\\n\",\"source\":\"/proc/sys/kernel/ostype\"},{\"key\":\"overflowgid\",\"value\":\"65534\\n\",\"source\":\"/proc/sys/kernel/overflowgid\"},{\"key\":\"overflowuid\",\"value\":\"65534\\n\",\"source\":\"/proc/sys/kernel/overflowuid\"},{\"key\":\"panic\",\"value\":\"10\\n\",\"source\":\"/proc/sys/kernel/panic\"},{\"key\":\"panic_on_io_nmi\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/panic_on_io_nmi\"},{\"key\":\"panic_on_oops\",\"value\":\"1\\n\",\"source\":\"/proc/sys/kernel/panic_on_oops\"},{\"key\":\"panic_on_rcu_stall\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/panic_on_rcu_stall\"},{\"key\":\"panic_on_stackoverflow\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/panic_on_stackoverflow\"},{\"key\":\"panic_on_unrecovered_nmi\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/panic_on_unrecovered_nmi\"},{\"key\":\"panic_on_warn\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/panic_on_warn\"},{\"key\":\"perf_cpu_time_max_percent\",\"value\":\"25\\n\",\"source\":\"/proc/sys/kernel/perf_cpu_time_max_percent\"},{\"key\":\"perf_event_max_contexts_per_stack\",\"value\":\"8\\n\",\"source\":\"/proc/sys/kernel/perf_event_max_contexts_per_stack\"},{\"key\":\"perf_event_max_sample_rate\",\"value\":\"100000\\n\",\"source\":\"/proc/sys/kernel/perf_event_max_sample_rate\"},{\"key\":\"perf_event_max_stack\",\"value\":\"127\\n\",\"source\":\"/proc/sys/kernel/perf_event_max_stack\"},{\"key\":\"perf_event_mlock_kb\",\"value\":\"516\\n\",\"source\":\"/proc/sys/kernel/perf_event_mlock_kb\"},{\"key\":\"perf_event_paranoid\",\"value\":\"2\\n\",\"source\":\"/proc/sys/kernel/perf_event_paranoid\"},{\"key\":\"pid_max\",\"value\":\"4194304\\n\",\"source\":\"/proc/sys/kernel/pid_max\"},{\"key\":\"poweroff_cmd\",\"value\":\"/sbin/poweroff\\n\",\"source\":\"/proc/sys/kernel/poweroff_cmd\"},{\"key\":\"print-fatal-signals\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/print-fatal-signals\"},{\"key\":\"printk\",\"value\":\"3\\t4\\t1\\t7\\n\",\"source\":\"/proc/sys/kernel/printk\"},{\"key\":\"printk_delay\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/printk_delay\"},{\"key\":\"printk_devkmsg\",\"value\":\"on\\n\",\"source\":\"/proc/sys/kernel/printk_devkmsg\"},{\"key\":\"printk_ratelimit\",\"value\":\"5\\n\",\"source\":\"/proc/sys/kernel/printk_ratelimit\"},{\"key\":\"printk_ratelimit_burst\",\"value\":\"10\\n\",\"source\":\"/proc/sys/kernel/printk_ratelimit_burst\"},{\"key\":\"max\",\"value\":\"4096\\n\",\"source\":\"/proc/sys/kernel/pty/max\"},{\"key\":\"nr\",\"value\":\"1\\n\",\"source\":\"/proc/sys/kernel/pty/nr\"},{\"key\":\"reserve\",\"value\":\"1024\\n\",\"source\":\"/proc/sys/kernel/pty/reserve\"},{\"key\":\"boot_id\",\"value\":\"7fbec4c7-1230-422f-95ce-5528cd1c54c4\\n\",\"source\":\"/proc/sys/kernel/random/boot_id\"},{\"key\":\"entropy_avail\",\"value\":\"3794\\n\",\"source\":\"/proc/sys/kernel/random/entropy_avail\"},{\"key\":\"poolsize\",\"value\":\"4096\\n\",\"source\":\"/proc/sys/kernel/random/poolsize\"},{\"key\":\"read_wakeup_threshold\",\"value\":\"64\\n\",\"source\":\"/proc/sys/kernel/random/read_wakeup_threshold\"},{\"key\":\"urandom_min_reseed_secs\",\"value\":\"60\\n\",\"source\":\"/proc/sys/kernel/random/urandom_min_reseed_secs\"},{\"key\":\"uuid\",\"value\":\"2889254b-e006-4e53-86b0-3155dc2361b9\\n\",\"source\":\"/proc/sys/kernel/random/uuid\"},{\"key\":\"write_wakeup_threshold\",\"value\":\"896\\n\",\"source\":\"/proc/sys/kernel/random/write_wakeup_threshold\"},{\"key\":\"randomize_va_space\",\"value\":\"2\\n\",\"source\":\"/proc/sys/kernel/randomize_va_space\"},{\"key\":\"real-root-dev\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/real-root-dev\"},{\"key\":\"sched_cfs_bandwidth_slice_us\",\"value\":\"5000\\n\",\"source\":\"/proc/sys/kernel/sched_cfs_bandwidth_slice_us\"},{\"key\":\"sched_child_runs_first\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/sched_child_runs_first\"},{\"key\":\"sched_rr_timeslice_ms\",\"value\":\"100\\n\",\"source\":\"/proc/sys/kernel/sched_rr_timeslice_ms\"},{\"key\":\"sched_rt_period_us\",\"value\":\"1000000\\n\",\"source\":\"/proc/sys/kernel/sched_rt_period_us\"},{\"key\":\"sched_rt_runtime_us\",\"value\":\"950000\\n\",\"source\":\"/proc/sys/kernel/sched_rt_runtime_us\"},{\"key\":\"actions_avail\",\"value\":\"kill_process kill_thread trap errno trace log allow\\n\",\"source\":\"/proc/sys/kernel/seccomp/actions_avail\"},{\"key\":\"actions_logged\",\"value\":\"kill_process kill_thread trap errno trace log\\n\",\"source\":\"/proc/sys/kernel/seccomp/actions_logged\"},{\"key\":\"sem\",\"value\":\"32000\\t1024000000\\t500\\t32000\\n\",\"source\":\"/proc/sys/kernel/sem\"},{\"key\":\"sg-big-buff\",\"value\":\"32768\\n\",\"source\":\"/proc/sys/kernel/sg-big-buff\"},{\"key\":\"shm_rmid_forced\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/shm_rmid_forced\"},{\"key\":\"shmall\",\"value\":\"18446744073692774399\\n\",\"source\":\"/proc/sys/kernel/shmall\"},{\"key\":\"shmmax\",\"value\":\"18446744073692774399\\n\",\"source\":\"/proc/sys/kernel/shmmax\"},{\"key\":\"shmmni\",\"value\":\"4096\\n\",\"source\":\"/proc/sys/kernel/shmmni\"},{\"key\":\"sysctl_writes_strict\",\"value\":\"1\\n\",\"source\":\"/proc/sys/kernel/sysctl_writes_strict\"},{\"key\":\"sysrq\",\"value\":\"16\\n\",\"source\":\"/proc/sys/kernel/sysrq\"},{\"key\":\"tainted\",\"value\":\"4096\\n\",\"source\":\"/proc/sys/kernel/tainted\"},{\"key\":\"threads-max\",\"value\":\"62033\\n\",\"source\":\"/proc/sys/kernel/threads-max\"},{\"key\":\"timer_migration\",\"value\":\"1\\n\",\"source\":\"/proc/sys/kernel/timer_migration\"},{\"key\":\"traceoff_on_warning\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/traceoff_on_warning\"},{\"key\":\"tracepoint_printk\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/tracepoint_printk\"},{\"key\":\"unknown_nmi_panic\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/unknown_nmi_panic\"},{\"key\":\"unprivileged_bpf_disabled\",\"value\":\"0\\n\",\"source\":\"/proc/sys/kernel/unprivileged_bpf_disabled\"},{\"key\":\"bset\",\"value\":\"4294967295\\t63\\n\",\"source\":\"/proc/sys/kernel/usermodehelper/bset\"},{\"key\":\"inheritable\",\"value\":\"4294967295\\t63\\n\",\"source\":\"/proc/sys/kernel/usermodehelper/inheritable\"},{\"key\":\"version\",\"value\":\"#1 SMP Wed Oct 27 22:52:27 UTC 2021\\n\",\"source\":\"/proc/sys/kernel/version\"}]\n"),
		{"http", "pod1", "7888", "/kubeletInfo"}:            []byte("{\"serviceFiles\":[{\"ownership\":{\"uid\":0,\"gid\":0,\"username\":\"root\",\"groupname\":\"root\"},\"path\":\"/etc/systemd/system/kubelet.service.d/10-kubeadm.conf\",\"permissions\":420}],\"configFile\":{\"ownership\":{\"uid\":0,\"gid\":0,\"username\":\"root\",\"groupname\":\"root\"},\"path\":\"/var/lib/kubelet/config.yaml\",\"content\":\"YXBpVmVyc2lvbjoga3ViZWxldC5jb25maWcuazhzLmlvL3YxYmV0YTEKYXV0aGVudGljYXRpb246CiAgYW5vbnltb3VzOgogICAgZW5hYmxlZDogZmFsc2UKICB3ZWJob29rOgogICAgY2FjaGVUVEw6IDBzCiAgICBlbmFibGVkOiB0cnVlCiAgeDUwOToKICAgIGNsaWVudENBRmlsZTogL3Zhci9saWIvbWluaWt1YmUvY2VydHMvY2EuY3J0CmF1dGhvcml6YXRpb246CiAgbW9kZTogV2ViaG9vawogIHdlYmhvb2s6CiAgICBjYWNoZUF1dGhvcml6ZWRUVEw6IDBzCiAgICBjYWNoZVVuYXV0aG9yaXplZFRUTDogMHMKY2dyb3VwRHJpdmVyOiBzeXN0ZW1kCmNsdXN0ZXJETlM6Ci0gMTAuOTYuMC4xMApjbHVzdGVyRG9tYWluOiBjbHVzdGVyLmxvY2FsCmNwdU1hbmFnZXJSZWNvbmNpbGVQZXJpb2Q6IDBzCmV2aWN0aW9uSGFyZDoKICBpbWFnZWZzLmF2YWlsYWJsZTogMCUKICBub2RlZnMuYXZhaWxhYmxlOiAwJQogIG5vZGVmcy5pbm9kZXNGcmVlOiAwJQpldmljdGlvblByZXNzdXJlVHJhbnNpdGlvblBlcmlvZDogMHMKZmFpbFN3YXBPbjogZmFsc2UKZmlsZUNoZWNrRnJlcXVlbmN5OiAwcwpoZWFsdGh6QmluZEFkZHJlc3M6IDEyNy4wLjAuMQpoZWFsdGh6UG9ydDogMTAyNDgKaHR0cENoZWNrRnJlcXVlbmN5OiAwcwppbWFnZUdDSGlnaFRocmVzaG9sZFBlcmNlbnQ6IDEwMAppbWFnZU1pbmltdW1HQ0FnZTogMHMKa2luZDogS3ViZWxldENvbmZpZ3VyYXRpb24KbG9nZ2luZzoge30KbWVtb3J5U3dhcDoge30Kbm9kZVN0YXR1c1JlcG9ydEZyZXF1ZW5jeTogMHMKbm9kZVN0YXR1c1VwZGF0ZUZyZXF1ZW5jeTogMHMKcmVzb2x2Q29uZjogL3J1bi9zeXN0ZW1kL3Jlc29sdmUvcmVzb2x2LmNvbmYKcm90YXRlQ2VydGlmaWNhdGVzOiB0cnVlCnJ1bnRpbWVSZXF1ZXN0VGltZW91dDogMHMKc2h1dGRvd25HcmFjZVBlcmlvZDogMHMKc2h1dGRvd25HcmFjZVBlcmlvZENyaXRpY2FsUG9kczogMHMKc3RhdGljUG9kUGF0aDogL2V0Yy9rdWJlcm5ldGVzL21hbmlmZXN0cwpzdHJlYW1pbmdDb25uZWN0aW9uSWRsZVRpbWVvdXQ6IDBzCnN5bmNGcmVxdWVuY3k6IDBzCnZvbHVtZVN0YXRzQWdnUGVyaW9kOiAwcwo=\",\"permissions\":420},\"kubeConfigFile\":{\"ownership\":{\"uid\":0,\"gid\":0,\"username\":\"root\",\"groupname\":\"root\"},\"path\":\"/etc/kubernetes/kubelet.conf\",\"content\":\"YXBpVmVyc2lvbjogdjEKY2x1c3RlcnM6Ci0gY2x1c3RlcjoKICAgIGNlcnRpZmljYXRlLWF1dGhvcml0eS1kYXRhOiBMUzB0TFMxQ1JVZEpUaUJEUlZKVVNVWkpRMEZVUlMwdExTMHRDazFKU1VSQ2FrTkRRV1UyWjBGM1NVSkJaMGxDUVZSQlRrSm5hM0ZvYTJsSE9YY3dRa0ZSYzBaQlJFRldUVkpOZDBWUldVUldVVkZFUlhkd2RHRlhOWEFLWVROV2FWcFZUa0pOUWpSWVJGUkplRTFFVFhsT2VrVXhUa1JSZUU1c2IxaEVWRTE0VFVSTmVVNXFSVEZPUkZGNFRteHZkMFpVUlZSTlFrVkhRVEZWUlFwQmVFMUxZbGRzZFdGWGRERlpiVlpFVVZSRFEwRlRTWGRFVVZsS1MyOWFTV2gyWTA1QlVVVkNRbEZCUkdkblJWQkJSRU5EUVZGdlEyZG5SVUpCVEZWSUNuVkNjamtyTWpJNGVGWldhVFZETUdoSFRHeFVlbE5EYXpjemJXOXNkbEZ1WXpGV1lpdHFNRmxtZUVjcmMwdDRXRFZvWVhGRFlVVlRObTVpU1ZaSWJsZ0tSVEI2Y0U5V2QybFdTR1JDUnpRNWNqVlNVQzlPVmpFclVVbG9lRkpPTlN0SE5raHJWbVpJVDFCcVJEZE5iVWRZYldSeGNWUnhXbU16ZG5JeVJYRk9Rd3B6VTFSTmJqYzVaR014TWs1RFRuTkVSM1l5ZUZKWFZuSmlkazlwTTNobmQzSXhiWGQyZDBoUGQyWnBXRGRLV1M5R2VFdHFkVGhYYmpFd1lrb3dVRk12Q25JeVJtdDNWRU5aUjJKQ1ZFNXdRblp1U25ka1lTdDZaWEJ4Y213MWEwaFVSemswVVRSbGRtNDRkRk4yZDBkeGQwaEthMHR2ZHpCM1FYRnlhV1ZPV1c0S2RFWTJZVFJtUzJOb1RpODRaRzF6Tmk5a2VsVmFUbWxhVFdObVNHWnRNekIxUW5jMGNUUkJVekI1ZFdsM1JHSnFRVVIzV1VRclRVeFdZbWwxU20xQldncEhkMVkxU0ZaeE9ISnFhMVZFVjNZcmVHUXdRMEYzUlVGQllVNW9UVVk0ZDBSbldVUldVakJRUVZGSUwwSkJVVVJCWjB0clRVSXdSMEV4VldSS1VWRlhDazFDVVVkRFEzTkhRVkZWUmtKM1RVTkNaMmR5UW1kRlJrSlJZMFJCVkVGUVFtZE9Wa2hTVFVKQlpqaEZRbFJCUkVGUlNDOU5RakJIUVRGVlpFUm5VVmNLUWtKU2JqWjBSemdyYUUxb2EwWnViSEZvUjIxb05EaHFlbkZHV2tkNlFVNUNaMnR4YUd0cFJ6bDNNRUpCVVhOR1FVRlBRMEZSUlVGcFV6WXpSbmR1UmdwYVFXbEJOM1paUVVGSWFHbzRWMHRJYzJwbVMxRkdhWHBRTlV4d2VXZFhlWE01VUVkTE9YbFVNMjlQVEdoT1lrRndjblpLUkhaREwweFVNakJwVkdzM0NtdDNTVlZxU1dsNU5XNW1VMEY1U1d4a1lXZENiRFYwWmpCdWEyVlZXVnBETjB3dldWZG1WazFqZDNjMWFsUkhlRWRVTjJaNlNsSmxkVXBTVXpCV2VHa0tjbk0xWmpCWU5GTm5UWEJMYzBzNVNIaEJabXBtVVhaMEwyWjJNRUk1U0RSSVExWnFlR0ZJUjBwWlQxQkRLMjFHVWtOTlJrdHNTSFF2VFVsR1RHaG9jd29yUWxadkszaE9WbHB4U2xGVmNWQm1PRzByTlUxVU55dGxOekZqWkRGc1dtazRTRXRzVldvelZuQXlNekJpUW0xVkwyOVBORlZaWlRaYWVrUm9Oa0ZHQ21oSFVrVkNjSGt2YW1Gb2ExaFRNa3M1TVcxNVV6SnZTVWRsYW1Wc1NsZEVla05GV0dKTlQyaHZPVkJxWkU5amRWTlRNR3A1U1RadVQyMUNjWFJ6TDJNS2RITlNlSEEwTDNVMFpsbGpiMUU5UFFvdExTMHRMVVZPUkNCRFJWSlVTVVpKUTBGVVJTMHRMUzB0Q2c9PQogICAgc2VydmVyOiBodHRwczovL2NvbnRyb2wtcGxhbmUubWluaWt1YmUuaW50ZXJuYWw6ODQ0MwogIG5hbWU6IG1rCmNvbnRleHRzOgotIGNvbnRleHQ6CiAgICBjbHVzdGVyOiBtawogICAgdXNlcjogc3lzdGVtOm5vZGU6bWluaWt1YmUKICBuYW1lOiBzeXN0ZW06bm9kZTptaW5pa3ViZUBtawpjdXJyZW50LWNvbnRleHQ6IHN5c3RlbTpub2RlOm1pbmlrdWJlQG1rCmtpbmQ6IENvbmZpZwpwcmVmZXJlbmNlczoge30KdXNlcnM6Ci0gbmFtZTogc3lzdGVtOm5vZGU6bWluaWt1YmUKICB1c2VyOgogICAgY2xpZW50LWNlcnRpZmljYXRlOiAvdmFyL2xpYi9rdWJlbGV0L3BraS9rdWJlbGV0LWNsaWVudC1jdXJyZW50LnBlbQogICAgY2xpZW50LWtleTogL3Zhci9saWIva3ViZWxldC9wa2kva3ViZWxldC1jbGllbnQtY3VycmVudC5wZW0K\",\"permissions\":384},\"clientCAFile\":{\"ownership\":{\"uid\":0,\"gid\":0,\"username\":\"root\",\"groupname\":\"root\"},\"path\":\"/var/lib/minikube/certs/ca.crt\",\"permissions\":420},\"cmdLine\":\"/var/lib/minikube/binaries/v1.22.3/kubelet --bootstrap-kubeconfig=/etc/kubernetes/bootstrap-kubelet.conf --config=/var/lib/kubelet/config.yaml --container-runtime=docker --hostname-override=minikube --kubeconfig=/etc/kubernetes/kubelet.conf --node-ip=192.168.59.101 \"}\n"),
		{"http", "pod2", "7888", "/kubeletInfo"}:            []byte("{\"serviceFiles\":[{\"ownership\":{\"uid\":0,\"gid\":0,\"username\":\"root\",\"groupname\":\"root\"},\"path\":\"/etc/systemd/system/kubelet.service.d/10-kubeadm.conf\",\"permissions\":420}],\"configFile\":{\"ownership\":{\"uid\":0,\"gid\":0,\"username\":\"root\",\"groupname\":\"root\"},\"path\":\"/var/lib/kubelet/config.yaml\",\"content\":\"YXBpVmVyc2lvbjoga3ViZWxldC5jb25maWcuazhzLmlvL3YxYmV0YTEKYXV0aGVudGljYXRpb246CiAgYW5vbnltb3VzOgogICAgZW5hYmxlZDogZmFsc2UKICB3ZWJob29rOgogICAgY2FjaGVUVEw6IDBzCiAgICBlbmFibGVkOiB0cnVlCiAgeDUwOToKICAgIGNsaWVudENBRmlsZTogL3Zhci9saWIvbWluaWt1YmUvY2VydHMvY2EuY3J0CmF1dGhvcml6YXRpb246CiAgbW9kZTogV2ViaG9vawogIHdlYmhvb2s6CiAgICBjYWNoZUF1dGhvcml6ZWRUVEw6IDBzCiAgICBjYWNoZVVuYXV0aG9yaXplZFRUTDogMHMKY2dyb3VwRHJpdmVyOiBzeXN0ZW1kCmNsdXN0ZXJETlM6Ci0gMTAuOTYuMC4xMApjbHVzdGVyRG9tYWluOiBjbHVzdGVyLmxvY2FsCmNwdU1hbmFnZXJSZWNvbmNpbGVQZXJpb2Q6IDBzCmV2aWN0aW9uSGFyZDoKICBpbWFnZWZzLmF2YWlsYWJsZTogMCUKICBub2RlZnMuYXZhaWxhYmxlOiAwJQogIG5vZGVmcy5pbm9kZXNGcmVlOiAwJQpldmljdGlvblByZXNzdXJlVHJhbnNpdGlvblBlcmlvZDogMHMKZmFpbFN3YXBPbjogZmFsc2UKZmlsZUNoZWNrRnJlcXVlbmN5OiAwcwpoZWFsdGh6QmluZEFkZHJlc3M6IDEyNy4wLjAuMQpoZWFsdGh6UG9ydDogMTAyNDgKaHR0cENoZWNrRnJlcXVlbmN5OiAwcwppbWFnZUdDSGlnaFRocmVzaG9sZFBlcmNlbnQ6IDEwMAppbWFnZU1pbmltdW1HQ0FnZTogMHMKa2luZDogS3ViZWxldENvbmZpZ3VyYXRpb24KbG9nZ2luZzoge30KbWVtb3J5U3dhcDoge30Kbm9kZVN0YXR1c1JlcG9ydEZyZXF1ZW5jeTogMHMKbm9kZVN0YXR1c1VwZGF0ZUZyZXF1ZW5jeTogMHMKcmVzb2x2Q29uZjogL3J1bi9zeXN0ZW1kL3Jlc29sdmUvcmVzb2x2LmNvbmYKcm90YXRlQ2VydGlmaWNhdGVzOiB0cnVlCnJ1bnRpbWVSZXF1ZXN0VGltZW91dDogMHMKc2h1dGRvd25HcmFjZVBlcmlvZDogMHMKc2h1dGRvd25HcmFjZVBlcmlvZENyaXRpY2FsUG9kczogMHMKc3RhdGljUG9kUGF0aDogL2V0Yy9rdWJlcm5ldGVzL21hbmlmZXN0cwpzdHJlYW1pbmdDb25uZWN0aW9uSWRsZVRpbWVvdXQ6IDBzCnN5bmNGcmVxdWVuY3k6IDBzCnZvbHVtZVN0YXRzQWdnUGVyaW9kOiAwcwo=\",\"permissions\":420},\"kubeConfigFile\":{\"ownership\":{\"uid\":0,\"gid\":0,\"username\":\"root\",\"groupname\":\"root\"},\"path\":\"/etc/kubernetes/kubelet.conf\",\"content\":\"YXBpVmVyc2lvbjogdjEKY2x1c3RlcnM6Ci0gY2x1c3RlcjoKICAgIGNlcnRpZmljYXRlLWF1dGhvcml0eS1kYXRhOiBMUzB0TFMxQ1JVZEpUaUJEUlZKVVNVWkpRMEZVUlMwdExTMHRDazFKU1VSQ2FrTkRRV1UyWjBGM1NVSkJaMGxDUVZSQlRrSm5hM0ZvYTJsSE9YY3dRa0ZSYzBaQlJFRldUVkpOZDBWUldVUldVVkZFUlhkd2RHRlhOWEFLWVROV2FWcFZUa0pOUWpSWVJGUkplRTFFVFhsT2VrVXhUa1JSZUU1c2IxaEVWRTE0VFVSTmVVNXFSVEZPUkZGNFRteHZkMFpVUlZSTlFrVkhRVEZWUlFwQmVFMUxZbGRzZFdGWGRERlpiVlpFVVZSRFEwRlRTWGRFVVZsS1MyOWFTV2gyWTA1QlVVVkNRbEZCUkdkblJWQkJSRU5EUVZGdlEyZG5SVUpCVEZWSUNuVkNjamtyTWpJNGVGWldhVFZETUdoSFRHeFVlbE5EYXpjemJXOXNkbEZ1WXpGV1lpdHFNRmxtZUVjcmMwdDRXRFZvWVhGRFlVVlRObTVpU1ZaSWJsZ0tSVEI2Y0U5V2QybFdTR1JDUnpRNWNqVlNVQzlPVmpFclVVbG9lRkpPTlN0SE5raHJWbVpJVDFCcVJEZE5iVWRZYldSeGNWUnhXbU16ZG5JeVJYRk9Rd3B6VTFSTmJqYzVaR014TWs1RFRuTkVSM1l5ZUZKWFZuSmlkazlwTTNobmQzSXhiWGQyZDBoUGQyWnBXRGRLV1M5R2VFdHFkVGhYYmpFd1lrb3dVRk12Q25JeVJtdDNWRU5aUjJKQ1ZFNXdRblp1U25ka1lTdDZaWEJ4Y213MWEwaFVSemswVVRSbGRtNDRkRk4yZDBkeGQwaEthMHR2ZHpCM1FYRnlhV1ZPV1c0S2RFWTJZVFJtUzJOb1RpODRaRzF6Tmk5a2VsVmFUbWxhVFdObVNHWnRNekIxUW5jMGNUUkJVekI1ZFdsM1JHSnFRVVIzV1VRclRVeFdZbWwxU20xQldncEhkMVkxU0ZaeE9ISnFhMVZFVjNZcmVHUXdRMEYzUlVGQllVNW9UVVk0ZDBSbldVUldVakJRUVZGSUwwSkJVVVJCWjB0clRVSXdSMEV4VldSS1VWRlhDazFDVVVkRFEzTkhRVkZWUmtKM1RVTkNaMmR5UW1kRlJrSlJZMFJCVkVGUVFtZE9Wa2hTVFVKQlpqaEZRbFJCUkVGUlNDOU5RakJIUVRGVlpFUm5VVmNLUWtKU2JqWjBSemdyYUUxb2EwWnViSEZvUjIxb05EaHFlbkZHV2tkNlFVNUNaMnR4YUd0cFJ6bDNNRUpCVVhOR1FVRlBRMEZSUlVGcFV6WXpSbmR1UmdwYVFXbEJOM1paUVVGSWFHbzRWMHRJYzJwbVMxRkdhWHBRTlV4d2VXZFhlWE01VUVkTE9YbFVNMjlQVEdoT1lrRndjblpLUkhaREwweFVNakJwVkdzM0NtdDNTVlZxU1dsNU5XNW1VMEY1U1d4a1lXZENiRFYwWmpCdWEyVlZXVnBETjB3dldWZG1WazFqZDNjMWFsUkhlRWRVTjJaNlNsSmxkVXBTVXpCV2VHa0tjbk0xWmpCWU5GTm5UWEJMYzBzNVNIaEJabXBtVVhaMEwyWjJNRUk1U0RSSVExWnFlR0ZJUjBwWlQxQkRLMjFHVWtOTlJrdHNTSFF2VFVsR1RHaG9jd29yUWxadkszaE9WbHB4U2xGVmNWQm1PRzByTlUxVU55dGxOekZqWkRGc1dtazRTRXRzVldvelZuQXlNekJpUW0xVkwyOVBORlZaWlRaYWVrUm9Oa0ZHQ21oSFVrVkNjSGt2YW1Gb2ExaFRNa3M1TVcxNVV6SnZTVWRsYW1Wc1NsZEVla05GV0dKTlQyaHZPVkJxWkU5amRWTlRNR3A1U1RadVQyMUNjWFJ6TDJNS2RITlNlSEEwTDNVMFpsbGpiMUU5UFFvdExTMHRMVVZPUkNCRFJWSlVTVVpKUTBGVVJTMHRMUzB0Q2c9PQogICAgc2VydmVyOiBodHRwczovL2NvbnRyb2wtcGxhbmUubWluaWt1YmUuaW50ZXJuYWw6ODQ0MwogIG5hbWU6IG1rCmNvbnRleHRzOgotIGNvbnRleHQ6CiAgICBjbHVzdGVyOiBtawogICAgdXNlcjogc3lzdGVtOm5vZGU6bWluaWt1YmUKICBuYW1lOiBzeXN0ZW06bm9kZTptaW5pa3ViZUBtawpjdXJyZW50LWNvbnRleHQ6IHN5c3RlbTpub2RlOm1pbmlrdWJlQG1rCmtpbmQ6IENvbmZpZwpwcmVmZXJlbmNlczoge30KdXNlcnM6Ci0gbmFtZTogc3lzdGVtOm5vZGU6bWluaWt1YmUKICB1c2VyOgogICAgY2xpZW50LWNlcnRpZmljYXRlOiAvdmFyL2xpYi9rdWJlbGV0L3BraS9rdWJlbGV0LWNsaWVudC1jdXJyZW50LnBlbQogICAgY2xpZW50LWtleTogL3Zhci9saWIva3ViZWxldC9wa2kva3ViZWxldC1jbGllbnQtY3VycmVudC5wZW0K\",\"permissions\":384},\"clientCAFile\":{\"ownership\":{\"uid\":0,\"gid\":0,\"username\":\"root\",\"groupname\":\"root\"},\"path\":\"/var/lib/minikube/certs/ca.crt\",\"permissions\":420},\"cmdLine\":\"/var/lib/minikube/binaries/v1.22.3/kubelet --bootstrap-kubeconfig=/etc/kubernetes/bootstrap-kubelet.conf --config=/var/lib/kubelet/config.yaml --container-runtime=docker --hostname-override=minikube --kubeconfig=/etc/kubernetes/kubelet.conf --node-ip=192.168.59.101 \"}\n"),
		{"http", "pod1", "7888", "/kubeProxyInfo"}:          []byte("{\"cmdLine\":\"/usr/local/bin/kube-proxy --config=/var/lib/kube-proxy/config.conf --hostname-override=minikube \"}\n"),
		{"http", "pod2", "7888", "/kubeProxyInfo"}:          []byte("{\"cmdLine\":\"/usr/local/bin/kube-proxy --config=/var/lib/kube-proxy/config.conf --hostname-override=minikube \"}\n"),
		{"http", "pod1", "7888", "/cloudProviderInfo"}:      []byte("{\"providerID\": \"foo\"}\n"),
		{"http", "pod2", "7888", "/cloudProviderInfo"}:      []byte("{\"providerID\": \"foo\"}\n"),
		{"http", "pod1", "7888", "/controlPlaneInfo"}:       []byte("{\"APIServerInfo\":{\"specsFile\":{\"ownership\":{\"uid\":0,\"gid\":0,\"username\":\"root\",\"groupname\":\"root\"},\"path\":\"/etc/kubernetes/manifests/kube-apiserver.yaml\",\"permissions\":384},\"cmdLine\":\"kube-apiserver --advertise-address=192.168.59.101 --allow-privileged=true --authorization-mode=Node,RBAC --client-ca-file=/var/lib/minikube/certs/ca.crt --enable-admission-plugins=NamespaceLifecycle,LimitRanger,ServiceAccount,DefaultStorageClass,DefaultTolerationSeconds,NodeRestriction,MutatingAdmissionWebhook,ValidatingAdmissionWebhook,ResourceQuota --enable-bootstrap-token-auth=true --etcd-cafile=/var/lib/minikube/certs/etcd/ca.crt --etcd-certfile=/var/lib/minikube/certs/apiserver-etcd-client.crt --etcd-keyfile=/var/lib/minikube/certs/apiserver-etcd-client.key --etcd-servers=https://127.0.0.1:2379 --kubelet-client-certificate=/var/lib/minikube/certs/apiserver-kubelet-client.crt --kubelet-client-key=/var/lib/minikube/certs/apiserver-kubelet-client.key --kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname --proxy-client-cert-file=/var/lib/minikube/certs/front-proxy-client.crt --proxy-client-key-file=/var/lib/minikube/certs/front-proxy-client.key --requestheader-allowed-names=front-proxy-client --requestheader-client-ca-file=/var/lib/minikube/certs/front-proxy-ca.crt --requestheader-extra-headers-prefix=X-Remote-Extra- --requestheader-group-headers=X-Remote-Group --requestheader-username-headers=X-Remote-User --secure-port=8443 --service-account-issuer=https://kubernetes.default.svc.cluster.local --service-account-key-file=/var/lib/minikube/certs/sa.pub --service-account-signing-key-file=/var/lib/minikube/certs/sa.key --service-cluster-ip-range=10.96.0.0/12 --tls-cert-file=/var/lib/minikube/certs/apiserver.crt --tls-private-key-file=/var/lib/minikube/certs/apiserver.key \"},\"controllerManagerInfo\":{\"specsFile\":{\"ownership\":{\"uid\":0,\"gid\":0,\"username\":\"root\",\"groupname\":\"root\"},\"path\":\"/etc/kubernetes/manifests/kube-controller-manager.yaml\",\"permissions\":384},\"configFile\":{\"ownership\":{\"uid\":0,\"gid\":0,\"username\":\"root\",\"groupname\":\"root\"},\"path\":\"/etc/kubernetes/controller-manager.conf\",\"permissions\":384},\"cmdLine\":\"kube-controller-manager --allocate-node-cidrs=true --authentication-kubeconfig=/etc/kubernetes/controller-manager.conf --authorization-kubeconfig=/etc/kubernetes/controller-manager.conf --bind-address=127.0.0.1 --client-ca-file=/var/lib/minikube/certs/ca.crt --cluster-cidr=10.244.0.0/16 --cluster-name=mk --cluster-signing-cert-file=/var/lib/minikube/certs/ca.crt --cluster-signing-key-file=/var/lib/minikube/certs/ca.key --controllers=*,bootstrapsigner,tokencleaner --kubeconfig=/etc/kubernetes/controller-manager.conf --leader-elect=false --port=0 --requestheader-client-ca-file=/var/lib/minikube/certs/front-proxy-ca.crt --root-ca-file=/var/lib/minikube/certs/ca.crt --service-account-private-key-file=/var/lib/minikube/certs/sa.key --service-cluster-ip-range=10.96.0.0/12 --use-service-account-credentials=true \"},\"schedulerInfo\":{\"specsFile\":{\"ownership\":{\"uid\":0,\"gid\":0,\"username\":\"root\",\"groupname\":\"root\"},\"path\":\"/etc/kubernetes/manifests/kube-scheduler.yaml\",\"permissions\":384},\"configFile\":{\"ownership\":{\"uid\":0,\"gid\":0,\"username\":\"root\",\"groupname\":\"root\"},\"path\":\"/etc/kubernetes/scheduler.conf\",\"permissions\":384},\"cmdLine\":\"kube-scheduler --authentication-kubeconfig=/etc/kubernetes/scheduler.conf --authorization-kubeconfig=/etc/kubernetes/scheduler.conf --bind-address=127.0.0.1 --kubeconfig=/etc/kubernetes/scheduler.conf --leader-elect=false --port=0 \"},\"etcdConfigFile\":{\"ownership\":{\"uid\":0,\"gid\":0,\"username\":\"root\",\"groupname\":\"root\"},\"path\":\"/etc/kubernetes/manifests/etcd.yaml\",\"permissions\":384},\"etcdDataDir\":{\"ownership\":{\"uid\":0,\"gid\":0,\"username\":\"root\",\"groupname\":\"root\"},\"path\":\"/var/lib/minikube/etcd\",\"permissions\":448},\"adminConfigFile\":{\"ownership\":{\"uid\":0,\"gid\":0,\"username\":\"root\",\"groupname\":\"root\"},\"path\":\"/etc/kubernetes/admin.conf\",\"permissions\":384}}\n"),
		{"http", "pod2", "7888", "/controlPlaneInfo"}:       []byte("{\"APIServerInfo\":{\"specsFile\":{\"ownership\":{\"uid\":0,\"gid\":0,\"username\":\"root\",\"groupname\":\"root\"},\"path\":\"/etc/kubernetes/manifests/kube-apiserver.yaml\",\"permissions\":384},\"cmdLine\":\"kube-apiserver --advertise-address=192.168.59.101 --allow-privileged=true --authorization-mode=Node,RBAC --client-ca-file=/var/lib/minikube/certs/ca.crt --enable-admission-plugins=NamespaceLifecycle,LimitRanger,ServiceAccount,DefaultStorageClass,DefaultTolerationSeconds,NodeRestriction,MutatingAdmissionWebhook,ValidatingAdmissionWebhook,ResourceQuota --enable-bootstrap-token-auth=true --etcd-cafile=/var/lib/minikube/certs/etcd/ca.crt --etcd-certfile=/var/lib/minikube/certs/apiserver-etcd-client.crt --etcd-keyfile=/var/lib/minikube/certs/apiserver-etcd-client.key --etcd-servers=https://127.0.0.1:2379 --kubelet-client-certificate=/var/lib/minikube/certs/apiserver-kubelet-client.crt --kubelet-client-key=/var/lib/minikube/certs/apiserver-kubelet-client.key --kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname --proxy-client-cert-file=/var/lib/minikube/certs/front-proxy-client.crt --proxy-client-key-file=/var/lib/minikube/certs/front-proxy-client.key --requestheader-allowed-names=front-proxy-client --requestheader-client-ca-file=/var/lib/minikube/certs/front-proxy-ca.crt --requestheader-extra-headers-prefix=X-Remote-Extra- --requestheader-group-headers=X-Remote-Group --requestheader-username-headers=X-Remote-User --secure-port=8443 --service-account-issuer=https://kubernetes.default.svc.cluster.local --service-account-key-file=/var/lib/minikube/certs/sa.pub --service-account-signing-key-file=/var/lib/minikube/certs/sa.key --service-cluster-ip-range=10.96.0.0/12 --tls-cert-file=/var/lib/minikube/certs/apiserver.crt --tls-private-key-file=/var/lib/minikube/certs/apiserver.key \"},\"controllerManagerInfo\":{\"specsFile\":{\"ownership\":{\"uid\":0,\"gid\":0,\"username\":\"root\",\"groupname\":\"root\"},\"path\":\"/etc/kubernetes/manifests/kube-controller-manager.yaml\",\"permissions\":384},\"configFile\":{\"ownership\":{\"uid\":0,\"gid\":0,\"username\":\"root\",\"groupname\":\"root\"},\"path\":\"/etc/kubernetes/controller-manager.conf\",\"permissions\":384},\"cmdLine\":\"kube-controller-manager --allocate-node-cidrs=true --authentication-kubeconfig=/etc/kubernetes/controller-manager.conf --authorization-kubeconfig=/etc/kubernetes/controller-manager.conf --bind-address=127.0.0.1 --client-ca-file=/var/lib/minikube/certs/ca.crt --cluster-cidr=10.244.0.0/16 --cluster-name=mk --cluster-signing-cert-file=/var/lib/minikube/certs/ca.crt --cluster-signing-key-file=/var/lib/minikube/certs/ca.key --controllers=*,bootstrapsigner,tokencleaner --kubeconfig=/etc/kubernetes/controller-manager.conf --leader-elect=false --port=0 --requestheader-client-ca-file=/var/lib/minikube/certs/front-proxy-ca.crt --root-ca-file=/var/lib/minikube/certs/ca.crt --service-account-private-key-file=/var/lib/minikube/certs/sa.key --service-cluster-ip-range=10.96.0.0/12 --use-service-account-credentials=true \"},\"schedulerInfo\":{\"specsFile\":{\"ownership\":{\"uid\":0,\"gid\":0,\"username\":\"root\",\"groupname\":\"root\"},\"path\":\"/etc/kubernetes/manifests/kube-scheduler.yaml\",\"permissions\":384},\"configFile\":{\"ownership\":{\"uid\":0,\"gid\":0,\"username\":\"root\",\"groupname\":\"root\"},\"path\":\"/etc/kubernetes/scheduler.conf\",\"permissions\":384},\"cmdLine\":\"kube-scheduler --authentication-kubeconfig=/etc/kubernetes/scheduler.conf --authorization-kubeconfig=/etc/kubernetes/scheduler.conf --bind-address=127.0.0.1 --kubeconfig=/etc/kubernetes/scheduler.conf --leader-elect=false --port=0 \"},\"etcdConfigFile\":{\"ownership\":{\"uid\":0,\"gid\":0,\"username\":\"root\",\"groupname\":\"root\"},\"path\":\"/etc/kubernetes/manifests/etcd.yaml\",\"permissions\":384},\"etcdDataDir\":{\"ownership\":{\"uid\":0,\"gid\":0,\"username\":\"root\",\"groupname\":\"root\"},\"path\":\"/var/lib/minikube/etcd\",\"permissions\":448},\"adminConfigFile\":{\"ownership\":{\"uid\":0,\"gid\":0,\"username\":\"root\",\"groupname\":\"root\"},\"path\":\"/etc/kubernetes/admin.conf\",\"permissions\":384}}\n"),
		{"http", "pod1", "7888", "/CNIInfo"}:                []byte("{\"CNIConfigFiles\":[{\"ownership\":{\"uid\":0,\"gid\":0,\"username\":\"root\",\"groupname\":\"root\"},\"path\":\"/etc/cni/net.d\",\"permissions\":493},{\"ownership\":{\"uid\":0,\"gid\":0,\"username\":\"root\",\"groupname\":\"root\"},\"path\":\"/etc/cni/net.d/.keep\",\"permissions\":420},{\"ownership\":{\"uid\":0,\"gid\":0,\"username\":\"root\",\"groupname\":\"root\"},\"path\":\"/etc/cni/net.d/87-podman-bridge.conflist\",\"permissions\":420}]}\n"),
		{"http", "pod2", "7888", "/CNIInfo"}:                []byte("{\"CNIConfigFiles\":[{\"ownership\":{\"uid\":0,\"gid\":0,\"username\":\"root\",\"groupname\":\"root\"},\"path\":\"/etc/cni/net.d\",\"permissions\":493},{\"ownership\":{\"uid\":0,\"gid\":0,\"username\":\"root\",\"groupname\":\"root\"},\"path\":\"/etc/cni/net.d/.keep\",\"permissions\":420},{\"ownership\":{\"uid\":0,\"gid\":0,\"username\":\"root\",\"groupname\":\"root\"},\"path\":\"/etc/cni/net.d/87-podman-bridge.conflist\",\"permissions\":420}]}\n"),
	}
}
