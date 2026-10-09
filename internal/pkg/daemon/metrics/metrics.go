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

package metrics

import (
	"fmt"
	"net/http"
	"strconv"
	"sync"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	ctrl "sigs.k8s.io/controller-runtime"

	api "sigs.k8s.io/security-profiles-operator/api/grpc/metrics"
)

// Metrics proxy required permissions
// +kubebuilder:rbac:groups=authentication.k8s.io,resources=tokenreviews,verbs=create
// +kubebuilder:rbac:groups=authorization.k8s.io,resources=subjectaccessreviews,verbs=create

// OpenShift cluster TLS profile detection and watch (ignored in other distros):
// +kubebuilder:rbac:groups=config.openshift.io,resources=clusteroperators,verbs=get
// +kubebuilder:rbac:groups=config.openshift.io,resources=apiservers,verbs=get;list;watch

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
	metricNameSeriesDropped         = "series_dropped_total"

	// Metrics label values.
	metricLabelValueProfileUpdate = "update"
	metricLabelValueProfileDelete = "delete"

	// Metrics labels.
	metricsLabelOperation      = "operation"
	metricsLabelContainer      = "container"
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
	metricsLabelMetric         = "metric"

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
	grpcServer                  *grpc.Server
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
	metricSeriesDropped         *prometheus.CounterVec
	// series drops the idle series of the per workload metrics.
	series     *seriesTracker
	stopSeries chan struct{}
	stopOnce   sync.Once
}

// New returns a new Metrics instance.
func New() *Metrics {
	return &Metrics{
		impl:       &defaultImpl{},
		log:        ctrl.Log.WithName("metrics"),
		series:     newSeriesTracker(),
		stopSeries: make(chan struct{}),
		metricSeccompProfile: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:      metricNameSeccompProfile,
				Namespace: metricNamespace,
				Help:      "Amount of seccomp profile operations.",
			},
			[]string{metricsLabelOperation},
		),
		metricSeccompProfileAudit: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:      metricNameSeccompProfileAudit,
				Namespace: metricNamespace,
				Help:      "Amount of seccomp profile audit operations. Requires the log-enricher to be enabled.",
			},
			[]string{
				metricsLabelNode,
				metricsLabelNamespace,
				metricsLabelPod,
				metricsLabelContainer,
				metricsLabelSyscall,
			},
		),
		metricSeccompProfileBpf: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:      metricNameSeccompProfileBpf,
				Namespace: metricNamespace,
				Help:      "Amount of seccomp profile bpf operations. Requires the bpf-recorder to be enabled.",
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
				Help:      "Amount of seccomp profile errors.",
			},
			[]string{metricsLabelReason},
		),
		metricSelinuxProfile: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:      metricNameSelinuxProfile,
				Namespace: metricNamespace,
				Help:      "Amount of selinux profile operations.",
			},
			[]string{metricsLabelOperation},
		),
		metricSelinuxProfileAudit: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:      metricNameSelinuxProfileAudit,
				Namespace: metricNamespace,
				Help:      "Amount of selinux profile audit operations. Requires the log-enricher to be enabled.",
			},
			[]string{
				metricsLabelNode,
				metricsLabelNamespace,
				metricsLabelPod,
				metricsLabelContainer,
				metricsLabelScontext,
				metricsLabelTcontext,
			},
		),
		metricSelinuxProfileError: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:      metricNameSelinuxProfileError,
				Namespace: metricNamespace,
				Help:      "Amount of selinux profile errors.",
			},
			[]string{metricsLabelReason},
		),
		metricAppArmorProfile: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:      metricNameAppArmorProfile,
				Namespace: metricNamespace,
				Help:      "Amount of AppArmor profile operations.",
			},
			[]string{metricsLabelOperation},
		),
		metricAppArmorProfileAudit: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:      metricNameAppArmorProfileAudit,
				Namespace: metricNamespace,
				Help:      "Amount of AppArmor profile audit operations. Requires the log-enricher to be enabled.",
			},
			[]string{
				metricsLabelNode,
				metricsLabelNamespace,
				metricsLabelPod,
				metricsLabelContainer,
				metricsLabelProfile,
				metricsLabelOperation,
				metricsLabelApparmor,
			},
		),
		metricAppArmorProfileError: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:      metricNameAppArmorProfileError,
				Namespace: metricNamespace,
				Help:      "Amount of AppArmor profile errors.",
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
				Help:      "Amount of AppArmor profile denials.",
			},
			[]string{
				metricsLabelProfile,
				metricsLabelOperation,
			},
		),
		metricSeriesDropped: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:      metricNameSeriesDropped,
				Namespace: metricNamespace,
				Help:      "Amount of per workload metric increments dropped for exceeding the series limit.",
			},
			[]string{metricsLabelMetric},
		),
	}
}

// SetMaxSeries sets the number of series each per workload metric keeps at
// most, zero keeps any number. The increments of further series are dropped
// and counted in the series_dropped_total metric.
func (m *Metrics) SetMaxSeries(maxSeries int) {
	m.series.setMaxSeries(maxSeries)
}

// incSeries increments the series of a per workload metric.
func (m *Metrics) incSeries(name string, vec *prometheus.CounterVec, labels ...string) {
	dropped := m.series.inc(vec, labels...)
	if dropped == 0 {
		return
	}

	m.metricSeriesDropped.WithLabelValues(name).Inc()

	// Only log every so often, a metric at its limit drops a lot.
	if dropped == 1 || dropped%seriesDropLogInterval == 0 {
		m.log.Info("Dropping metrics because the metric has too many series",
			"metric", name, "dropped", dropped)
	}
}

// Register iterates over all available metrics and registers them.
func (m *Metrics) Register() error {
	for name, collector := range m.Collectors() {
		m.log.Info("Registering metric", "name", name)

		if err := m.impl.Register(collector); err != nil {
			return fmt.Errorf("register collector for %s metric: %w", name, err)
		}
	}

	return nil
}

// Collectors returns the collectors of all metrics by their name.
func (m *Metrics) Collectors() map[string]prometheus.Collector {
	return map[string]prometheus.Collector{
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
		metricNameSeriesDropped:         m.metricSeriesDropped,
	}
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
	node, namespace, pod, container, syscall string,
) {
	m.incSeries(metricNameSeccompProfileAudit, m.metricSeccompProfileAudit,
		node, namespace, pod, container, syscall,
	)
}

// IncSeccompProfileBpf increments the seccomp profile bpf counter for the
// provided labels.
func (m *Metrics) IncSeccompProfileBpf(
	node, profile string, mountNamespace uint32,
) {
	m.incSeries(metricNameSeccompProfileBpf, m.metricSeccompProfileBpf,
		node, strconv.FormatUint(uint64(mountNamespace), 10), profile,
	)
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
	node, namespace, pod, container, scontext, tcontext string,
) {
	m.incSeries(metricNameSelinuxProfileAudit, m.metricSelinuxProfileAudit,
		node, namespace, pod, container, scontext, tcontext,
	)
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
	node, namespace, pod, container, profile, operation, apparmor string,
) {
	m.incSeries(metricNameAppArmorProfileAudit, m.metricAppArmorProfileAudit,
		node, namespace, pod, container, profile, operation, apparmor,
	)

	if apparmor == apparmorDeniedAction {
		m.IncAppArmorProfileDenial(profile, operation)
	}
}

// IncAppArmorProfileError increments the apparmor profile error counter for the
// provided profile and reason.
func (m *Metrics) IncAppArmorProfileError(profile, reason string) {
	m.metricAppArmorProfileError.WithLabelValues(profile, reason).Inc()
}

// IncAppArmorProfileDenial increments the apparmor denial counter for the
// operation being denied in a profile.
func (m *Metrics) IncAppArmorProfileDenial(profile, operation string) {
	m.metricAppArmorProfileDenial.WithLabelValues(profile, operation).Inc()
}
