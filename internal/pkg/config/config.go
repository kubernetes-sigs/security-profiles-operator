/*
Copyright The Kubernetes Authors.

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
	"io/fs"
	"os"
	"path"
	"strconv"
	"sync"
)

const (
	// OperatorName is the name when referring to the operator.
	OperatorName = "security-profiles-operator"

	// SPOdName is the name of the default SPOd config instance.
	SPOdName = "spod"

	// SPOdServiceAccount is the service account for the security-profiles-operator daemon.
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

	// PodNameEnvKey is the environment variable key for retrieving the name
	// of the pod of the daemon.
	PodNameEnvKey = "POD_NAME"

	// RestrictNamespaceEnvKey is the environment variable key for restricting
	// the operator to work on only a single Kubernetes namespace.
	RestrictNamespaceEnvKey = "RESTRICT_TO_NAMESPACE"

	// VerbosityEnvKey is the environment variable key for the logging verbosity.
	VerbosityEnvKey = "SPO_VERBOSITY"

	// EnableLogEnricherEnvKey is the environment variable key for enabling the log enricher.
	EnableLogEnricherEnvKey = "ENABLE_LOG_ENRICHER"

	// EnableJsonEnricherEnvKey is the environment variable key for enabling the JSON enricher.
	EnableJsonEnricherEnvKey = "ENABLE_JSON_ENRICHER"

	// EnableBpfRecorderEnvKey is the environment variable key for enabling the BPF recorder.
	EnableBpfRecorderEnvKey = "ENABLE_BPF_RECORDER"

	// EnableRecordingEnvKey is the environment variable key to enabling profile recording.
	EnableRecordingEnvKey = "ENABLE_RECORDING"

	// EnableSeccompEnvKey is the environment variable key for enabling seccomp support.
	EnableSeccompEnvKey = "ENABLE_SECCOMP"

	// EnableSelinuxEnvKey is the environment variable key for enabling SELinux support.
	EnableSelinuxEnvKey = "ENABLE_SELINUX"

	// EnableApparmorEnvKey is the environment variable key for enabling AppArmor support.
	EnableApparmorEnvKey = "ENABLE_APPARMOR"

	// EnableRawSelinuxEnvKey is the environment variable key for enabling raw SELinux support.
	EnableRawSelinuxEnvKey = "ENABLE_RAW_SELINUX"

	// EnableMemOptimEnvKey is the environment variable key for enabling memory optimization.
	EnableMemOptimEnvKey = "ENABLE_MEM_OPTIM"

	// EnableInsecureMetricsAccessEnvKey is the environment variable key for allowing unauthenticated
	// access to metrics endpoint.
	EnableInsecureMetricsAccessEnvKey = "ENABLE_INSECURE_METRICS_ACCESS"

	// MaxMetricSeriesEnvKey is the environment variable key for the number of
	// series each per workload metric of the daemon keeps at most.
	MaxMetricSeriesEnvKey = "MAX_METRIC_SERIES"

	// VerboseLevel is the increased verbosity log level.
	VerboseLevel = 1

	// ProfilingEnvKey is the environment variable key for enabling profiling
	// support.
	ProfilingEnvKey = "SPO_PROFILING"

	// ProfilingPortEnvKey is the environment variable key for choosing the
	// profiling port.
	ProfilingPortEnvKey = "SPO_PROFILING_PORT"

	// ProfilingAddressEnvKey is the environment variable key for choosing
	// the address the profiling endpoint binds to.
	ProfilingAddressEnvKey = "SPO_PROFILING_ADDRESS"

	// DefaultProfilingAddress is the address the profiling endpoint binds to
	// per default, which keeps it off the pod network.
	DefaultProfilingAddress = "127.0.0.1"

	// AllInterfacesAddress is the address which binds to all interfaces.
	AllInterfacesAddress = "0.0.0.0"

	// KubeletDirEnvKey is the environment variable key for custom kubelet directory.
	KubeletDirEnvKey = "KUBELET_DIR"

	// AppArmorEnvKey is the environment variable key for enabling apaprmor profiles for
	// security-profiles-operator itself.
	AppArmorEnvKey = "SPO_APPARMOR"

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

	// ApparmorProfileRecordBpfAnnotationKey is the annotation on a Pod that
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

	// SpoSeccompProfile is the file name of the seccomp profile of the
	// containers of the spod daemonset, which the non-root enabler copies
	// into the seccomp directory of the kubelet.
	SpoSeccompProfile = "security-profiles-operator.json"

	// BpfRecorderSeccompProfile is the file name of the seccomp profile of the
	// bpf-recorder container, which the non-root enabler copies into the
	// seccomp directory of the kubelet.
	BpfRecorderSeccompProfile = "bpf-recorder.json"

	// OCIProfilePrefix is the prefix used for specifying security profiles
	// from OCI artifacts.
	OCIProfilePrefix = "oci://"

	// SpoApparmorProfile is the default file name for apparmor profile used by
	// the security-profiles-operator container part of spod daemonset.
	SpoApparmorProfile = "spo-apparmor.yaml"

	// SpoApparmorProfileName is the name of the apparmor profile used by the
	// security-profiles-operator container part of spod daemonset.
	SpoApparmorProfileName = "spo-apparmor"

	// BpfRecorderApparmorProfile is the default file name for apparmor profile used
	// by the bpf-recorder container part of spod daemonset.
	BpfRecorderApparmorProfile = "bpfrecorder-apparmor.yaml"

	// BpfRecorderApparmorProfileName is the name of the apparmor profile used by
	// the bpf-recorder container part of spod dameonset.
	BpfRecorderApparmorProfileName = "bpfrecorder-apparmor"
)

var ErrPodNamespaceEnvNotFound = errors.New("the env variable OPERATOR_NAMESPACE hasn't been set")

// KubeletConfig stores various configuration parameters of the kubelet.
type KubeletConfig struct {
	// KubeletDir kubelet root directory path
	KubeletDir string `json:"kubeletDir,omitempty"`
}

// TryToGetOperatorNamespace returns the namespace the operator runs in, which
// the downward API provides in the environment.
func TryToGetOperatorNamespace() (string, error) {
	// This is OPERATOR_NAMESPACE should have been set by the downward API to identify
	// the namespace which this controller is running from
	operatorNS := os.Getenv(OperatorNamespaceEnvKey)
	if operatorNS == "" {
		return "", ErrPodNamespaceEnvNotFound
	}

	return operatorNS, nil
}

// WatchNamespaces returns the comma separated namespaces which the manager
// cache is restricted to, empty if it covers all namespaces. WATCH_NAMESPACE is
// used if RestrictNamespaceEnvKey is not set.
func WatchNamespaces() string {
	if namespaces, ok := os.LookupEnv(RestrictNamespaceEnvKey); ok {
		return namespaces
	}

	return os.Getenv("WATCH_NAMESPACE")
}

// EnvEnabled returns true if the environment variable is a true boolean, like
// the ones which enable the recorders and enrichers. Values which are not a
// boolean count as false.
func EnvEnabled(key string) bool {
	value, err := strconv.ParseBool(os.Getenv(key))

	return err == nil && value
}

// KubeletDir returns the kubelet directory either from the kubelet config
// file, which the non-root enabler writes, from an environment variable when
// it is set, or the default Kubernetes path. The file is read on every call,
// because the non-root enabler may write it after the daemon started.
func KubeletDir() string {
	return kubeletDir(KubeletConfigFilePath())
}

// kubeletDir is KubeletDir with the kubelet config file at configPath.
func kubeletDir(configPath string) string {
	cfg, err := readKubeletConfig(configPath)
	if err == nil && cfg.KubeletDir != "" {
		return cfg.KubeletDir
	}

	// A missing file is expected without the non-root enabler, any other
	// error falls back as well, but is worth knowing about. The callers have
	// no logger at hand, and the path is looked up on every reconciliation,
	// so the warning goes to stderr once.
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		warnKubeletConfig.Do(func() {
			fmt.Fprintf(os.Stderr, "Using the default kubelet directory: %v\n", err)
		})
	}

	return DefaultKubeletDir()
}

// warnKubeletConfig reports an unusable kubelet config file once.
var warnKubeletConfig sync.Once

// DefaultKubeletDir returns the kubelet directory from the environment
// variable if set, or the default Kubernetes path. Unlike KubeletDir it
// ignores the kubelet config file, which the non-root enabler persists on the
// node and which therefore can be outdated.
func DefaultKubeletDir() string {
	kubeletDir := os.Getenv(KubeletDirEnvKey)
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
	return readKubeletConfig(KubeletConfigFilePath())
}

// readKubeletConfig reads the kubelet config from the file at configPath.
func readKubeletConfig(configPath string) (*KubeletConfig, error) {
	cfg, err := os.ReadFile(configPath) //nolint:gosec // the path of the operator, not user input
	if err != nil {
		return nil, fmt.Errorf("reading kubelet config: %w", err)
	}

	kubeletCfg := &KubeletConfig{}
	if err := json.Unmarshal(cfg, kubeletCfg); err != nil {
		return nil, fmt.Errorf("parsing kubelet config: %w", err)
	}

	return kubeletCfg, nil
}
