package hostsensorutils

const hostSensorYAML = `
apiVersion: v1
kind: Namespace
metadata:
  labels:
    app: host-sensor
    kubernetes.io/metadata.name: armo-kube-host-sensor
    tier: armo-kube-host-sensor-control-plane
  name: armo-kube-host-sensor
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: host-sensor
  namespace: armo-kube-host-sensor
  labels:
    k8s-app: armo-kube-host-sensor
spec:
  selector:
    matchLabels:
      name: host-sensor
  template:
    metadata:
      labels:
        name: host-sensor
    spec:
      tolerations:
      # this toleration is to have the daemonset runnable on master nodes
      # remove it if your masters can't run pods
      - key: node-role.kubernetes.io/master
        operator: Exists
        effect: NoSchedule
      containers:
      - name: host-sensor
        image: quay.io/armosec/kube-host-sensor:latest
        securityContext:
          privileged: true
          readOnlyRootFilesystem: true
          procMount: Unmasked
        ports:
          - name: http
            hostPort: 7888
            containerPort: 7888
        resources:
          limits:
            cpu: 1m
            memory: 200Mi
          requests:
            cpu: 1m
            memory: 200Mi
        volumeMounts:
        - mountPath: /host_fs
          name: host-filesystem
      terminationGracePeriodSeconds: 120
      dnsPolicy: ClusterFirstWithHostNet
      automountServiceAccountToken: false
      volumes:
      - hostPath:
          path: /
          type: Directory
        name: host-filesystem
      hostNetwork: true
      hostPID: true
      hostIPC: true

    

      `
