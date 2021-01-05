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

package selinuxpolicy

import (
	"context"
	"fmt"
	"time"

	rcommonv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	spov1alpha1 "sigs.k8s.io/security-profiles-operator/api/selinuxpolicy/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

// blank assignment to verify that ReconcileConfigMap implements `reconcile.Reconciler`.
var _ reconcile.Reconciler = &ReconcileConfigMap{}

const defaultRequeueTime = 5 * time.Second

// ReconcileConfigMap reconciles a ConfigMap object.
type ReconcileConfigMap struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client client.Client
	scheme *runtime.Scheme
	record event.Recorder
}

// Reconcile reads that state of the cluster for a ConfigMap object and makes changes based on the state read
// and what is in the `ConfigMap.Spec`.
func (r *ReconcileConfigMap) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	// Fetch the ConfigMap instance
	cminstance := &corev1.ConfigMap{}
	if err := r.client.Get(context.TODO(), request.NamespacedName, cminstance); err != nil {
		return reconcile.Result{}, IgnoreNotFound(err)
	}
	policyName, ok := cminstance.Labels["appName"]
	if !ok {
		return reconcile.Result{}, nil
	}
	policyNamespace, ok := cminstance.Labels["appNamespace"]
	if !ok {
		return reconcile.Result{}, nil
	}

	reqLogger := log.WithValues("SelinuxPolicy.Name", policyName, "SelinuxPolicy.Namespace", policyNamespace)

	policyObjKey := types.NamespacedName{Name: policyName, Namespace: policyNamespace}
	policy := &spov1alpha1.SelinuxPolicy{}
	if err := r.client.Get(context.TODO(), policyObjKey, policy); err != nil {
		return reconcile.Result{}, IgnoreNotFound(err)
	}

	if policy.Status.State == "" || policy.Status.State == spov1alpha1.PolicyStatePending {
		policyCopy := policy.DeepCopy()
		policyCopy.Status.State = spov1alpha1.PolicyStateInProgress
		policyCopy.Status.SetConditions(rcommonv1.Creating())
		if err := r.client.Status().Update(context.TODO(), policyCopy); err != nil {
			return reconcile.Result{}, errors.Wrap(err, "Updating policy without status")
		}
		return reconcile.Result{Requeue: true}, nil
	}

	// object is not being deleted
	if cminstance.ObjectMeta.DeletionTimestamp.IsZero() {
		return r.reconcileInstallerPods(policy, cminstance, reqLogger)
	}
	return reconcile.Result{}, nil
}

func (r *ReconcileConfigMap) reconcileInstallerPods(policy *spov1alpha1.SelinuxPolicy, cm *corev1.ConfigMap,
	logger logr.Logger) (reconcile.Result, error) {
	var done bool
	logger.Info("Reconciling pods for policy")

	nodesList := &corev1.NodeList{}
	if err := r.client.List(context.TODO(), nodesList); err != nil {
		return reconcile.Result{}, errors.Wrap(err, "Getting node list")
	}
	for nodeidx := range nodesList.Items {
		// Define a new Pod object
		pod := newPodForPolicy(policy.GetName(), policy.GetNamespace(), &nodesList.Items[nodeidx])
		if err := controllerutil.SetControllerReference(cm, pod, r.scheme); err != nil {
			log.Error(err, "Failed to set pod ownership", "pod", pod)
			return reconcile.Result{}, errors.Wrap(err, "Setting controller reference for SELinux installer pod")
		}

		// Check if this Pod already exists
		found := &corev1.Pod{}
		err := r.client.Get(context.TODO(), types.NamespacedName{Name: pod.Name, Namespace: pod.Namespace}, found)
		if err != nil && kerrors.IsNotFound(err) {
			logger.Info("Creating a new Pod", "Pod.Namespace", pod.Namespace, "Pod.Name", pod.Name)
			if err = r.client.Create(context.TODO(), pod); err != nil {
				return reconcile.Result{}, IgnoreAlreadyExists(err)
			}
			// NOTE(jaosorior): We expedite the creation of all
			// these pods...
			continue
		} else if err != nil {
			return reconcile.Result{}, errors.Wrap(err, "Gettting selinux installer Pod")
		}

		exitCode, gotCode := r.getInstallerContainerExitCode(found)
		// Pod is still running - requeue
		if !gotCode {
			logger.Info("Pod still running", "Pod.Namespace", pod.Namespace, "Pod.Name", pod.Name)
			return reconcile.Result{Requeue: true, RequeueAfter: defaultRequeueTime}, nil
		}
		if exitCode != 0 {
			logger.Info("Pod failed", "Pod.Namespace", pod.Namespace, "Pod.Name", pod.Name, "exit-code", exitCode)
			policyCopy := policy.DeepCopy()
			policyCopy.Status.State = spov1alpha1.PolicyStateError
			policyCopy.Status.SetConditions(rcommonv1.Unavailable())
			if err := r.client.Status().Update(context.TODO(), policyCopy); err != nil {
				return reconcile.Result{}, errors.Wrap(err, "Updating SELinux policy with install error")
			}
			return reconcile.Result{}, nil
		}
		done = true
	}

	if done {
		policyCopy := policy.DeepCopy()
		policyCopy.Status.State = spov1alpha1.PolicyStateInstalled
		policyCopy.Status.SetConditions(rcommonv1.Available())
		if err := r.client.Status().Update(context.TODO(), policyCopy); err != nil {
			return reconcile.Result{}, errors.Wrap(err, "Updating SELinux policy with installation success")
		}
	}
	return reconcile.Result{}, nil
}

func (r *ReconcileConfigMap) getInstallerContainerExitCode(pod *corev1.Pod) (int32, bool) {
	for idx := range pod.Status.ContainerStatuses {
		containerStatus := &pod.Status.ContainerStatuses[idx]
		if containerStatus.Name == "policy-installer" {
			if containerStatus.State.Terminated != nil {
				termState := containerStatus.State.Terminated
				return termState.ExitCode, true
			}
		}
	}
	return -1, false
}

// newPodForPolicy returns a busybox pod with the same name/namespace as the cr.
func newPodForPolicy(name, ns string, node *corev1.Node) *corev1.Pod {
	labels := map[string]string{
		"appName":      name,
		"appNamespace": ns,
	}
	trueVal := true
	hostVolTypeDir := corev1.HostPathDirectory
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      GetInstallerPodName(name, ns, node),
			Namespace: config.GetOperatorNamespace(),
			Labels:    labels,
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name: "policy-installer",
					// TODO(jaosorior): Add udica image or equivalent to a
					// more formal registry
					Image:   "quay.io/jaosorior/udica",
					Command: []string{"/bin/sh"},
					Args:    []string{"-c", "semodule -vi /tmp/policy/*.cil /usr/share/udica/templates/*cil;"},
					SecurityContext: &corev1.SecurityContext{
						Privileged: &trueVal,
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "fsselinux",
							MountPath: "/sys/fs/selinux",
						},
						{
							Name:      "etcselinux",
							MountPath: "/etc/selinux",
						},
						{
							Name:      "varlibselinux",
							MountPath: "/var/lib/selinux",
						},
						{
							Name:      "policyvolume",
							MountPath: "/tmp/policy",
						},
					},
				},
				// This container needs to keep running so we can run the uninstall script.
				{
					Name: "policy-uninstaller",
					// NOTE(jaosorior): Add udica image or equivalent to a
					// more formal registry
					Image:   "quay.io/jaosorior/udica",
					Command: []string{"/bin/sh"},
					Args:    []string{"-c", "trap 'exit 0' SIGINT SIGTERM; while true; do sleep infinity; done;"},
					Lifecycle: &corev1.Lifecycle{
						PreStop: &corev1.Handler{
							Exec: &corev1.ExecAction{
								Command: []string{"/bin/sh", "-c", fmt.Sprintf("semodule -vr '%s'", GetPolicyName(name, ns))},
							},
						},
					},
					SecurityContext: &corev1.SecurityContext{
						Privileged: &trueVal,
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "fsselinux",
							MountPath: "/sys/fs/selinux",
						},
						{
							Name:      "etcselinux",
							MountPath: "/etc/selinux",
						},
						{
							Name:      "varlibselinux",
							MountPath: "/var/lib/selinux",
						},
						{
							Name:      "policyvolume",
							MountPath: "/tmp/policy",
						},
					},
				},
			},
			// NOTE(jaosorior): use another service account
			ServiceAccountName: "security-profiles-operator",
			RestartPolicy:      corev1.RestartPolicyNever,
			NodeName:           node.Name,
			Volumes: []corev1.Volume{
				{
					Name: "fsselinux",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/sys/fs/selinux",
							Type: &hostVolTypeDir,
						},
					},
				},
				{
					Name: "etcselinux",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/etc/selinux",
							Type: &hostVolTypeDir,
						},
					},
				},
				{
					Name: "varlibselinux",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/var/lib/selinux",
							Type: &hostVolTypeDir,
						},
					},
				},
				{
					Name: "policyvolume",
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: GetPolicyConfigMapName(name, ns),
							},
						},
					},
				},
			},
			Tolerations: []corev1.Toleration{
				{
					Key:      "node-role.kubernetes.io/master",
					Operator: "Exists",
					Effect:   "NoSchedule",
				},
			},
		},
	}
}
