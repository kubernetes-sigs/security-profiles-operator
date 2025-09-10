# Configuring JSON Log Enricher for Audit Logging on Kubernetes Nodes

## Introduction

This is a user guide to configure audit logging in a single node local Kubernetes cluster using the JSON log enricher feature. The same steps can be used for multi-node clusters and managed clusters as well. This guide provides step-by-step instructions for configuring audit logging and viewing the generated logs.

Please note this is a user guide. Detailed documentation is available at [installation-usage.md](../installation-usage.md).

The use case involves two personas:
- **Auditor**: Configures the audit logging system and views the generated audit logs
- **Cluster Administrator/Support Person**: Performs administrative tasks such as exec into pods or nodes, whose activities are being audited

## Prerequisites

To follow this guide, you'll need a Kubernetes cluster and a few command-line tools. We're using a single-node cluster ([hack/local-up-cluster.sh](https://github.com/kubernetes/kubernetes/blob/801ee44/hack/local-up-cluster.sh)) for demonstration. The process works on any Kubernetes cluster.

- **Kubernetes Cluster**: The commands in this guide have been tested on Kubernetes v1.34.
- **kubectl**: The command-line tool for interacting with your cluster. We use the feature [kubectl debug: add label for debugger pod](https://github.com/kubernetes/kubernetes/pull/131791) for easy cleanup of debug pods, so Kubernetes v1.34 version and above of the client is recommended.

## Step 1: Install the Security-Profiles-Operator

Install the SPO by following the detailed installation instructions at [Install Operator](../installation-usage.md#install-operator).

## Step 2: Configure SPO to Store Logs Locally

To configure SPO to store logs on the host, create a JSON patch file.

Create a file named `patch-volume-source.json` with the following content:

```json
{
  "data": {
    "json-enricher-log-volume-mount-path": "/tmp/logs",
    "json-enricher-log-volume-source.json": "{\"hostPath\": {\"path\": \"/tmp/logs\",\"type\": \"DirectoryOrCreate\"}}"
  }
}
```

Apply the patch and restart the operator to activate the changes:

```bash
kubectl patch configmap security-profiles-operator-profile -n security-profiles-operator --patch-file patch-volume-source.json
kubectl rollout restart deployment security-profiles-operator -n security-profiles-operator
```

## Step 3: Enable JSON Logging and Filters

Patch the SPOD daemon set to enable the JSON Enricher and filter logs for user activity.

```bash
kubectl -n security-profiles-operator patch spod spod --type=merge -p '{"spec":{ "enableJsonEnricher":true,"verbosity":0,"jsonEnricherOptions":{"auditLogIntervalSeconds":20,"auditLogPath":"/tmp/logs/audit1.log","auditLogMaxSize":500,"auditLogMaxBackups":2,"auditLogMaxAge":10}, "jsonEnricherFilters":"[{\"priority\":100,\"level\":\"Metadata\",\"matchKeys\":[\"requestUID\"]},{\"priority\":999, \"level\":\"None\",\"matchKeys\":[\"version\"],\"matchValues\":[\"spo/v1_alpha\"]}]"}}'
```

## Step 4: Create and Apply a Seccomp Profile

This profile logs specific syscalls related to process creation.

Create a file named `sec_comp_profile.yaml`:

```yaml
apiVersion: security-profiles-operator.x-k8s.io/v1beta1
kind: SeccompProfile
metadata:
  name: profile1
spec:
  defaultAction: SCMP_ACT_ALLOW
  syscalls:
  - action: SCMP_ACT_LOG
    names:
    - execve
    - clone
    - fork
    - execveat
```

Apply the profile to your cluster:

```bash
kubectl apply -f sec_comp_profile.yaml
```

## Step 5: Bind the Profile to a Namespace

This will automatically apply the profile to new pods in the default namespace.

Create a file named `image_sec_comp.yaml`:

```yaml
apiVersion: security-profiles-operator.x-k8s.io/v1alpha1
kind: ProfileBinding
metadata:
  namespace: default
  name: all-pod-binding
spec:
  profileRef:
    kind: SeccompProfile
    name: profile1
  image: "*"
```

Apply the binding and label the namespace to activate it:

```bash
kubectl apply -f image_sec_comp.yaml
kubectl label ns default spo.x-k8s.io/enable-binding=true
```

## Step 6: Verify the Auditing

Create a test pod:

```bash
kubectl run my-nginx-pod --image=nginx --restart=Never
```

Exec into the pod and run a command:

```bash
kubectl exec -it my-nginx-pod -- /bin/sh
# touch demo-file
# exit
```

Check the logs on the host node at the `/tmp/logs/audit1.log` path. You should see a JSON entry capturing the command.

## Step 7: Auditing Node Debugging Sessions

To audit kubectl debug sessions, run the following command. The activity will be logged to the same file.

```bash
kubectl debug node/127.0.0.1 -it --image=ubuntu -- bash
root@ngopalak-ubuntu:/# touch demonodedebug
root@ngopalak-ubuntu:/# exit
```

## Step 8: Correlate with Kubernetes Audit Logs

Use the requestUID from the SPO log to find the corresponding API server log entry, confirming who initiated the session.

```bash
cat /tmp/kube-apiserver-audit.log | grep <requestUID>
```

## Step 9 (For CRI-O): Enable Privileged Seccomp Profiles

If you are using the CRI-O runtime, you must configure it to allow Seccomp profiles on privileged containers. Add the following flag to your CRI-O runtime configuration:

```bash
--privileged-seccomp-profile=/var/lib/kubelet/seccomp/operator/profile1.json
```

## Conclusion

You have successfully configured the JSON log enricher for audit logging on your Kubernetes cluster. The system will now capture and log administrative activities such as pod exec and node debugging sessions. 

For detailed documentation and additional configuration options, please refer to the [installation-usage.md](../installation-usage.md) file.