/*
Copyright 2021 The Kubernetes Authors.

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

package metrics

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	ctrl "sigs.k8s.io/controller-runtime"

	api "sigs.k8s.io/security-profiles-operator/api/grpc/metrics"
)

// Metrics proxy required permissions
// +kubebuilder:rbac:groups=authentication.k8s.io,resources=tokenreviews;subjectaccessreviews,verbs=create
// +kubebuilder:rbac:groups=authorization.k8s.io,resources=subjectaccessreviews,verbs=create

const (
	metricNamespace = "security_profiles_operator"

	// Metrics names.
	metricNameSeccompProfile        = "seccomp_profile_total"
	metricNameSelinuxProfile        = "selinux_profile_total"
	metricNameAppArmorProfile       = "apparmor_profile_total"
	metricNameSeccompProfileAudit   = "seccomp_profile_audit_total"
	metricNameSelinuxProfileAudit   = "selinux_profile_audit_total"
	metricNameAppArmorProfileAudit  = "apparmor_profile_audit_total"
	metricNameSeccompProfileBpf     = "seccomp_profile_bpf_total"
	metricNameSeccompProfileError   = "seccomp_profile_error_total"
	metricNameSelinuxProfileError   = "selinux_profile_error_total"
	metricNameAppArmorProfileError  = "apparmor_profile_error_total"
	metricNameAppArmorProfileDenial = "apparmor_profile_denial_total"

	// Metrics label values.
	metricLabelValueProfileUpdate = "update"
	metricLabelValueProfileDelete = "delete"

	// Metrics labels.
	metricLabelOperation       = "operation"
	metricsLabelContainer      = "container"
	metricsLabelExecutable     = "executable"
	metricsLabelNamespace      = "namespace"
	metricsLabelNode           = "node"
	metricsLabelPod            = "pod"
	metricsLabelReason         = "reason"
	metricsLabelSyscall        = "syscall"
	metricsLabelProfile        = "profile"
	metricsLabelScontext       = "scontext"
	metricsLabelTcontext       = "tcontext"
	metricsLabelMountNamespace = "mount_namespace"
	metricsLabelApparmor       = "apparmor"
	metricsLabelName           = "name"

	// HandlerPath is the default path for serving metrics.
	HandlerPath = "/metrics-spod"

	// Apparmor actions.
	apparmorDeniedAction = "DENIED"
)

// Metrics is the main structure of this package.
type Metrics struct {
	api.UnimplementedMetricsServer
	impl                        impl
	log                         logr.Logger
	metricSeccompProfile        *prometheus.CounterVec
	metricSeccompProfileAudit   *prometheus.CounterVec
	metricSeccompProfileBpf     *prometheus.CounterVec
	metricSeccompProfileError   *prometheus.CounterVec
	metricSelinuxProfile        *prometheus.CounterVec
	metricSelinuxProfileAudit   *prometheus.CounterVec
	metricSelinuxProfileError   *prometheus.CounterVec
	metricAppArmorProfile       *prometheus.CounterVec
	metricAppArmorProfileAudit  *prometheus.CounterVec
	metricAppArmorProfileError  *prometheus.CounterVec
	metricAppArmorProfileDenial *prometheus.CounterVec
}

// New returns a new Metrics instance.
func New() *Metrics {
	return &Metrics{
		impl: &defaultImpl{},
		log:  ctrl.Log.WithName("metrics"),
		metricSeccompProfile: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:      metricNameSeccompProfile,
				Namespace: metricNamespace,
				Help:      "Counter about seccomp profile operations.",
			},
			[]string{metricLabelOperation},
		),
		metricSeccompProfileAudit: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:      metricNameSeccompProfileAudit,
				Namespace: metricNamespace,
				Help:      "Counter about seccomp profile audits, requires the log enricher to be enabled.",
			},
			[]string{
				metricsLabelNode,
				metricsLabelNamespace,
				metricsLabelPod,
				metricsLabelContainer,
				metricsLabelExecutable,
				metricsLabelSyscall,
			},
		),
		metricSeccompProfileBpf: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:      metricNameSeccompProfileBpf,
				Namespace: metricNamespace,
				Help:      "Counter about seccomp profile bpf events, requires the bpf recorder to be enabled.",
			},
			[]string{
				metricsLabelNode,
				metricsLabelMountNamespace,
				metricsLabelProfile,
			},
		),
		metricSeccompProfileError: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:      metricNameSeccompProfileError,
				Namespace: metricNamespace,
				Help:      "Counter about seccomp profile errors.",
			},
			[]string{metricsLabelReason},
		),
		metricSelinuxProfile: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:      metricNameSelinuxProfile,
				Namespace: metricNamespace,
				Help:      "Counter about selinux profile operations.",
			},
			[]string{metricLabelOperation},
		),
		metricSelinuxProfileAudit: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:      metricNameSelinuxProfileAudit,
				Namespace: metricNamespace,
				Help:      "Counter about selinux profile audits, requires the log enricher to be enabled.",
			},
			[]string{
				metricsLabelNode,
				metricsLabelNamespace,
				metricsLabelPod,
				metricsLabelContainer,
				metricsLabelExecutable,
				metricsLabelScontext,
				metricsLabelTcontext,
			},
		),
		metricSelinuxProfileError: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:      metricNameSelinuxProfileError,
				Namespace: metricNamespace,
				Help:      "Counter about selinux profile errors.",
			},
			[]string{metricsLabelReason},
		),
		metricAppArmorProfile: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:      metricNameAppArmorProfile,
				Namespace: metricNamespace,
				Help:      "Counter about apparmor profile operations.",
			},
			[]string{metricLabelOperation},
		),
		metricAppArmorProfileAudit: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:      metricNameAppArmorProfileAudit,
				Namespace: metricNamespace,
				Help:      "Counter about apparmor profile audits, requires the log enricher to be enabled.",
			},
			[]string{
				metricsLabelNode,
				metricsLabelNamespace,
				metricsLabelPod,
				metricsLabelContainer,
				metricsLabelExecutable,
				metricsLabelProfile,
				metricLabelOperation,
				metricsLabelApparmor,
				metricsLabelName,
			},
		),
		metricAppArmorProfileError: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:      metricNameAppArmorProfileError,
				Namespace: metricNamespace,
				Help:      "Counter about apparmor profile errors.",
			},
			[]string{
				metricsLabelProfile,
				metricsLabelReason,
			},
		),
		metricAppArmorProfileDenial: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:      metricNameAppArmorProfileDenial,
				Namespace: metricNamespace,
				Help:      "Counter about apparmor profile denial.",
			},
			[]string{
				metricsLabelProfile,
				metricLabelOperation,
			},
		),
	}
}

// Register iterates over all available metrics and registers them.
func (m *Metrics) Register() error {
	for name, collector := range map[string]prometheus.Collector{
		metricNameSeccompProfile:        m.metricSeccompProfile,
		metricNameSeccompProfileAudit:   m.metricSeccompProfileAudit,
		metricNameSeccompProfileBpf:     m.metricSeccompProfileBpf,
		metricNameSeccompProfileError:   m.metricSeccompProfileError,
		metricNameSelinuxProfile:        m.metricSelinuxProfile,
		metricNameSelinuxProfileAudit:   m.metricSelinuxProfileAudit,
		metricNameSelinuxProfileError:   m.metricSelinuxProfileError,
		metricNameAppArmorProfile:       m.metricAppArmorProfile,
		metricNameAppArmorProfileAudit:  m.metricAppArmorProfileAudit,
		metricNameAppArmorProfileError:  m.metricAppArmorProfileError,
		metricNameAppArmorProfileDenial: m.metricAppArmorProfileDenial,
	} {
		m.log.Info("Registering metric: " + name)

		if err := m.impl.Register(collector); err != nil {
			return fmt.Errorf("register collector for %s metric: %w", name, err)
		}
	}

	return nil
}

// Handler creates an HTTP handler for the metrics.
func (m *Metrics) Handler() http.Handler {
	handler := &http.ServeMux{}
	handler.Handle(HandlerPath, promhttp.Handler())

	return handler
}

// IncSeccompProfileUpdate increments the seccomp profile update counter.
func (m *Metrics) IncSeccompProfileUpdate() {
	m.metricSeccompProfile.
		WithLabelValues(metricLabelValueProfileUpdate).Inc()
}

// IncSeccompProfileDelete increments the seccomp profile deletion counter.
func (m *Metrics) IncSeccompProfileDelete() {
	m.metricSeccompProfile.
		WithLabelValues(metricLabelValueProfileDelete).Inc()
}

// IncSeccompProfileAudit increments the seccomp profile audit counter for the
// provided labels.
func (m *Metrics) IncSeccompProfileAudit(
	node, namespace, pod, container, executable, syscall string,
) {
	m.metricSeccompProfileAudit.WithLabelValues(
		node, namespace, pod, container, executable, syscall,
	).Inc()
}

// IncSeccompProfileBpf increments the seccomp profile bpf counter for the
// provided labels.
func (m *Metrics) IncSeccompProfileBpf(
	node, profile string, mountNamespace uint32,
) {
	m.metricSeccompProfileBpf.WithLabelValues(
		node, strconv.FormatUint(uint64(mountNamespace), 10), profile,
	).Inc()
}

// IncSeccompProfileError increments the seccomp profile error counter for the
// provided reason.
func (m *Metrics) IncSeccompProfileError(reason string) {
	m.metricSeccompProfileError.WithLabelValues(reason).Inc()
}

// IncSelinuxProfileUpdate increments the selinux profile update counter.
func (m *Metrics) IncSelinuxProfileUpdate() {
	m.metricSelinuxProfile.
		WithLabelValues(metricLabelValueProfileUpdate).Inc()
}

// IncSelinuxProfileDelete increments the selinux profile deletion counter.
func (m *Metrics) IncSelinuxProfileDelete() {
	m.metricSelinuxProfile.
		WithLabelValues(metricLabelValueProfileDelete).Inc()
}

// IncSelinuxProfileAudit increments the selinux profile audit counter for the
// provided labels.
func (m *Metrics) IncSelinuxProfileAudit(
	node, namespace, pod, container, executable, scontext, tcontext string,
) {
	m.metricSelinuxProfileAudit.WithLabelValues(
		node, namespace, pod, container, executable, scontext, tcontext,
	).Inc()
}

// IncSelinuxProfileError increments the selinux profile error counter for the
// provided reason.
func (m *Metrics) IncSelinuxProfileError(reason string) {
	m.metricSelinuxProfileError.WithLabelValues(reason).Inc()
}

// IncAppArmorProfileUpdate increments the apparmor profile update counter.
func (m *Metrics) IncAppArmorProfileUpdate() {
	m.metricAppArmorProfile.
		WithLabelValues(metricLabelValueProfileUpdate).Inc()
}

// IncAppArmorProfileDelete increments the apparmor profile deletion counter.
func (m *Metrics) IncAppArmorProfileDelete() {
	m.metricAppArmorProfile.
		WithLabelValues(metricLabelValueProfileDelete).Inc()
}

// IncAppArmorProfileAudit increments the apparmor profile audit counter for the
// provided labels.
func (m *Metrics) IncAppArmorProfileAudit(
	node, namespace, pod, container, executable, profile, operation, apparmor, name string,
) {
	m.metricAppArmorProfileAudit.WithLabelValues(
		node, namespace, pod, container, executable, profile, operation, apparmor, name,
	).Inc()

	if apparmor == apparmorDeniedAction {
		m.IncAppArmorProfileDenial(profile, operation)
	}
}

// IncAppArmorProfileError increments the apparmor profile error counter for the
// provided reason.
func (m *Metrics) IncAppArmorProfileError(profile, reason string) {
	m.metricAppArmorProfileError.WithLabelValues(profile, reason).Inc()
}

// IncAppArmorProfileDenial increments the apparmor denial counter for the
// operation being denied in a profile.
func (m *Metrics) IncAppArmorProfileDenial(profile, operation string) {
	m.metricAppArmorProfileDenial.WithLabelValues(profile, operation).Inc()
}
