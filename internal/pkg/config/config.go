/*
Copyright 2020 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"

	"sigs.k8s.io/release-utils/env"
)

const (
	// OperatorName is the name when referring to the operator.
	OperatorName = "security-profiles-operator"

	// SPOdName is the name of the default SPOd config instance.
	SPOdName = "spod"

	// Service Account for the security-profiles-operator daemon.
	SPOdServiceAccount = SPOdName

	// SPOdNameEnvKey allows one to query the name of the SPOd instance
	// from within the daemon.
	SPOdNameEnvKey = "SPOD_NAME"

	// HostRoot define the host files root mount path.
	HostRoot = "/host"

	// SeccompProfilesFolder defines the folder name where the seccomp
	// profiles are stored.
	SeccompProfilesFolder = "seccomp"

	// OperatorProfilesFolder defines the folder name where the operator
	// profiles are stored.
	OperatorProfilesFolder = "operator"

	// OperatorRoot is the root directory of the operator.
	OperatorRoot = "/var/lib/security-profiles-operator"

	// UserRootless is the user which runs the operator.
	UserRootless = 65535

	// DefaultKubeletPath specifies the default kubelet path.
	DefaultKubeletPath = "/var/lib/kubelet"

	// KubeletConfigFile specifies the name of the kubelet config file
	// which contains various configuration parameters of the kubelet.
	// This configuration file is created by the non-root enabler container
	// during the daemon initialization.
	KubeletConfigFile = "kubelet-config.json"

	// NodeNameEnvKey is the default environment variable key for retrieving
	// the name of the current node.
	NodeNameEnvKey = "NODE_NAME"

	// OperatorNamespaceEnvKey is the default environment variable key for retrieving
	// the operator's namespace.
	OperatorNamespaceEnvKey = "OPERATOR_NAMESPACE"

	// RestrictNamespaceEnvKey is the environment variable key for restricting
	// the operator to work on only a single Kubernetes namespace.
	RestrictNamespaceEnvKey = "RESTRICT_TO_NAMESPACE"

	// VerbosityEnvKey is the environment variable key for the logging verbosity.
	VerbosityEnvKey = "SPO_VERBOSITY"

	// EnableLogEnricherEnvKey is the environment variable key for enabling the log enricher.
	EnableLogEnricherEnvKey = "ENABLE_LOG_ENRICHER"

	// EnableBpfRecorderEnvKey is the environment variable key for enabling the BPF recorder.
	EnableBpfRecorderEnvKey = "ENABLE_BPF_RECORDER"

	// EnableRecordingEnvKey is the environment variable key to enabling profile recording.
	EnableRecordingEnvKey = "ENABLE_RECORDING"

	// VerboseLevel is the increased verbosity log level.
	VerboseLevel = 1

	// ProfilingEnvKey is the environment variable key for enabling profiling
	// support.
	ProfilingEnvKey = "SPO_PROFILING"

	// ProfilingPortEnvKey is the environment variable key for choosing the
	// profiling port.
	ProfilingPortEnvKey = "SPO_PROFILING_PORT"

	// KubeletDirEnvKey is the environment variable key for custom kubelet directory.
	KubeletDirEnvKey = "KUBELET_DIR"

	// DefaultProfilingPort is the start port where the profiling endpoint runs.
	DefaultProfilingPort = 6060

	// SeccompProfileRecordLogsAnnotationKey is the annotation on a Pod that
	// triggers the internal log enricher to trace the syscalls of a Pod and
	// creates a seccomp profile.
	SeccompProfileRecordLogsAnnotationKey = "io.containers.trace-logs/"

	// SeccompProfileRecordBpfAnnotationKey is the annotation on a Pod that
	// triggers the internal bpf module to trace the syscalls of a Pod and
	// creates a seccomp profile.
	SeccompProfileRecordBpfAnnotationKey = "io.containers.trace-bpf/"

	// ApparmorProfilerRecordBpfAnnotationKey is the annotation on a Pod that
	// triggers the internal bpf module to trace the apparmor profile of a Pod
	// and creates a apparmor profile.
	ApparmorProfileRecordBpfAnnotationKey = "io.containers.trace-bpf-apparmor/"

	// SelinuxProfileRecordLogsAnnotationKey is the annotation on a Pod that
	// triggers the internal log enricher to trace the AVC denials of a Pod and
	// creates a selinux profile.
	SelinuxProfileRecordLogsAnnotationKey = "io.containers.trace-avcs/"

	// KubeletDirNodeLabelKey is the label on a Node that specifies
	// a custom kubelet root directory configured for this node. The directory
	// path is provided in the following format folder-subfolder-subfolder
	// which translates to /folder/subfolder/subfolder.
	KubeletDirNodeLabelKey = "kubelet.kubernetes.io/directory-location"

	// HealthProbePort is the port where the liveness probe will be served.
	HealthProbePort = 8085

	// AuditLogPath is the path to the auditd log file.
	AuditLogPath = "/var/log/audit/audit.log"

	// SyslogLogPath is the path to the syslog log file.
	SyslogLogPath = "/var/log/syslog"

	// LogEnricherProfile is the seccomp profile name for tracing syscalls from
	// the log enricher.
	LogEnricherProfile = "log-enricher-trace"

	// SelinuxPermissiveProfile is the selinux profile name for tracing AVC from
	// the log enricher.
	SelinuxPermissiveProfile = "selinuxrecording.process"

	// GRPCServerSocketMetrics is the socket path for the GRPC metrics server.
	GRPCServerSocketMetrics = "/var/run/grpc/metrics.sock"

	// GRPCServerSocketEnricher is the socket path for the GRPC enricher server.
	GRPCServerSocketEnricher = "/var/run/grpc/enricher.sock"

	// GRPCServerSocketBpfRecorder is the socket path for the GRPC bpf recorder server.
	GRPCServerSocketBpfRecorder = "/var/run/grpc/bpf-recorder.sock"

	// DefaultSpoProfilePath default path from where the security profiles are copied
	// by non-root enabler.
	DefaultSpoProfilePath = "/opt/spo-profiles"

	// OCIProfilePrefix is the prefix used for specifying security profiles
	// from OCI artifacts.
	OCIProfilePrefix = "oci://"
)

// ProfileRecordingOutputPath is the path where the recorded profiles will be
// stored. Those profiles are going to be reconciled into native CRDs and
// therefore have a limited lifetime.
var ProfileRecordingOutputPath = filepath.Join(os.TempDir(), "security-profiles-operator-recordings")

var ErrPodNamespaceEnvNotFound = errors.New("the env variable OPERATOR_NAMESPACE hasn't been set")

// KubeletConfig stores various configuration parameters of the kubelet.
type KubeletConfig struct {
	// KubeletDir kubelet root directory path
	KubeletDir string `json:"kubeletDir,omitempty"`
}

// GetOperatorNamespace gets the namespace that the operator is currently running on.
// Failure to get the namespace results in a panic.
func GetOperatorNamespace() string {
	ns, err := TryToGetOperatorNamespace()
	if err != nil {
		panic(err)
	}
	return ns
}

func TryToGetOperatorNamespace() (string, error) {
	// This is OPERATOR_NAMESPACE should have been set by the downward API to identify
	// the namespace which this controller is running from
	operatorNS := env.Default(OperatorNamespaceEnvKey, "")
	if operatorNS == "" {
		return "", ErrPodNamespaceEnvNotFound
	}
	return operatorNS, nil
}

// KubeletDir returns the kubelet directory either form a config file, an environment variable
// when is set or the default Kubernetes path.
func KubeletDir() string {
	cfg, err := GetKubeletConfigFromFile()
	if err == nil {
		return cfg.KubeletDir
	}
	kubeletDir := env.Default(KubeletDirEnvKey, "")
	if kubeletDir == "" {
		return DefaultKubeletPath
	}
	return kubeletDir
}

// KubeletSeccompRootPath specifies the path where all kubelet seccomp
// profiles are stored.
func KubeletSeccompRootPath() string {
	return path.Join(KubeletDir(), SeccompProfilesFolder)
}

// ProfilesRootPath specifies the path where the operator stores seccomp
// profiles.
func ProfilesRootPath() string {
	return path.Join(KubeletSeccompRootPath(), OperatorProfilesFolder)
}

// KubeletConfigFilePath returns the kubelet config file path.
func KubeletConfigFilePath() string {
	return path.Join(OperatorRoot, KubeletConfigFile)
}

// GetKubeletConfigFromFile reads the kubelet config from file.
func GetKubeletConfigFromFile() (*KubeletConfig, error) {
	cfg, err := os.ReadFile(KubeletConfigFilePath())
	if err != nil {
		return nil, fmt.Errorf("reading kubelet config: %w", err)
	}
	kubeletCfg := &KubeletConfig{}
	if err := json.Unmarshal(cfg, kubeletCfg); err != nil {
		return nil, fmt.Errorf("parsing kubelet config: %w", err)
	}
	return kubeletCfg, nil
}
