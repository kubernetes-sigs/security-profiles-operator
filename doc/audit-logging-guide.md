# Configuring JSON Log Enricher for Audit Logging on Kubernetes Nodes

## Introduction

This is a user guide to configure audit logging in a single node local Kubernetes cluster using the JSON log enricher feature. The same steps can be used for multi-node clusters and managed clusters as well. This guide provides step-by-step instructions for configuring audit logging and viewing the generated logs.

Please note this is a user guide. Detailed documentation is available at [profiles.md](profiles.md).

The use case involves two personas:
- **Auditor**: Configures the audit logging system and views the generated audit logs
- **Cluster Administrator/Support Person**: Performs administrative tasks such as exec into pods or nodes, whose activities are being audited

## Prerequisites

To follow this guide, you'll need a Kubernetes cluster and a few command-line tools. We're using a single-node cluster ([hack/local-up-cluster.sh](https://github.com/kubernetes/kubernetes/blob/801ee44/hack/local-up-cluster.sh)) for demonstration. The process works on any Kubernetes cluster.

- **Kubernetes Cluster**: A cluster which meets the [requirements](installation.md#requirements) of the operator.
- **kubectl**: The command-line tool for interacting with your cluster. We use the label which `kubectl debug` adds to the debugger pods ([kubectl debug: add label for debugger pod](https://github.com/kubernetes/kubernetes/pull/131791)) for easy cleanup of debug pods, so use a client release which includes that change.

## Step 1: Install the Security-Profiles-Operator

Install the SPO by following the detailed installation instructions at [Install Operator](installation.md#install-operator).

## Step 2: Configure SPO to Store Logs Locally

Mount the host directory `/tmp/logs` into the JSON enricher by following step 1 of
[Audit Log File Destination](profiles.md#audit-log-file-destination), which configures the volume. The operator picks up
the change without a restart.

## Step 3: Enable JSON Logging and Filters

Patch the SPOD to enable the JSON enricher, write the audit log to `/tmp/logs/audit1.log` and filter the logs for
user activity. The rotation options are described in
[Audit Log File Fine-Tuning (Rotation)](profiles.md#audit-log-file-fine-tuning-rotation) and the filters in
[Filtering Logs](profiles.md#filtering-logs).

```bash
kubectl -n security-profiles-operator patch spod spod --type=merge -p '{"spec":{"verbosity":0,"enricher":{"enableJsonEnricher":true,"jsonEnricherOptions":{"auditLogIntervalSeconds":20,"auditLogPath":"/tmp/logs/audit1.log","auditLogMaxSize":500,"auditLogMaxBackups":2,"auditLogMaxAge":10}, "jsonEnricherFilters":"[{\"priority\":100,\"level\":\"Metadata\",\"matchKeys\":[\"requestUID\"]},{\"priority\":999, \"level\":\"None\",\"matchKeys\":[\"version\"],\"matchValues\":[\"spo/v1_alpha\"]}]"}}}'
```

## Step 4: Create and Apply a Seccomp Profile

This profile logs specific syscalls related to process creation.

Create a file named `sec_comp_profile.yaml`:

```yaml
apiVersion: security-profiles-operator.x-k8s.io/v1
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
apiVersion: security-profiles-operator.x-k8s.io/v1
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

To audit kubectl debug sessions, run the following command, where `my-node` is the name of your node. The activity will be logged to the same file.

```bash
kubectl debug node/my-node -it --image=ubuntu -- bash
root@my-node:/# touch demonodedebug
root@my-node:/# exit
```

## Step 8: Correlate with Kubernetes Audit Logs

Use the requestUID from the SPO log to find the corresponding API server log entry, which records who initiated the session.

```bash
cat /tmp/kube-apiserver-audit.log | grep <requestUID>
```

The requestUID comes from an environment variable of the audited process, which the workload can set or unset, so it
is a best effort hint and not audit evidence. See
[Correlating with API Server Audit Log](profiles.md#correlating-with-api-server-audit-log).

## Step 9 (For CRI-O): Enable Privileged Seccomp Profiles

If you are using the CRI-O runtime, you must configure it to allow Seccomp profiles on privileged containers. Add the following flag to your CRI-O runtime configuration:

```bash
--privileged-seccomp-profile=/var/lib/kubelet/seccomp/operator/profile1.json
```

## Conclusion

You have successfully configured the JSON log enricher for audit logging on your Kubernetes cluster. The system will now capture and log administrative activities such as pod exec and node debugging sessions. 

For detailed documentation and additional configuration options, please refer to the [profiles](profiles.md) documentation.
