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

package profilerecorder

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/crossplane/crossplane-runtime/pkg/resource"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"sigs.k8s.io/security-profiles-operator/api/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

const (
	// default reconcile timeout.
	reconcileTimeout = 1 * time.Minute

	maxTraceAnnotations = 2

	errGetClient         = "cannot get client connection"
	errGetNode           = "cannot get node object"
	errGetPod            = "cannot get pod"
	errInvalidAnnotation = "invalid Annotation"

	// traceAnnotation is the annotation on a Pod that triggers the
	// oci-seccomp-bpf-hook to trace the syscalls of a Pod and created a
	// seccomp profile.
	traceAnnotation = "io.containers.trace-syscall"

	reasonProfileRecording      event.Reason = "SeccompProfileRecording"
	reasonProfileCreated        event.Reason = "SeccompProfileCreated"
	reasonProfileCreationFailed event.Reason = "CannotCreateSeccompProfile"
)

type RecorderReconciler struct {
	client      client.Client
	log         logr.Logger
	record      event.Recorder
	nodeAddress string
	podsToWatch map[string]string
}

func (r *RecorderReconciler) isPodOnLocalNode(obj runtime.Object) bool {
	p, ok := obj.(*corev1.Pod)

	if !ok {
		return false
	}
	r.log.Info("isPodOnLocalNode", "pod", p.Status.HostIP, "Node", r.nodeAddress)

	return p.Status.HostIP == r.nodeAddress
}

func (r *RecorderReconciler) isPodWithTraceAnnotation(obj runtime.Object) bool {
	p, ok := obj.(*corev1.Pod)

	if !ok {
		return false
	}

	r.log.Info("isPodWithTraceAnnotation", "Annotation",
		p.Annotations["io.containers.trace-syscall"])

	return p.Annotations["io.containers.trace-syscall"] != ""
}

func Setup(mgr ctrl.Manager, l logr.Logger) error {
	const name = "profilerecorder"
	c, err := client.New(mgr.GetConfig(), client.Options{})
	if err != nil {
		return errors.Wrap(err, errGetClient)
	}

	node := &corev1.Node{}
	err = c.Get(context.Background(), client.ObjectKey{Name: os.Getenv(config.NodeNameEnvKey)}, node)
	if err != nil {
		return errors.Wrap(err, errGetNode)
	}

	nodeAddress := ""

	for _, addr := range node.Status.Addresses {
		if addr.Type == "InternalIP" {
			l.Info("Setting up profile recorder", "Node", addr.Address)
			nodeAddress = addr.Address
			break
		}
	}

	if nodeAddress == "" {
		return errors.New("Unable to get node's internal Address")
	}

	reconiler := RecorderReconciler{
		client:      mgr.GetClient(),
		log:         l,
		nodeAddress: nodeAddress,
		record:      event.NewAPIRecorder(mgr.GetEventRecorderFor(name)),
		podsToWatch: map[string]string{},
	}

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithEventFilter(predicate.And(
			resource.NewPredicates(reconiler.isPodWithTraceAnnotation),
			resource.NewPredicates(reconiler.isPodOnLocalNode),
		)).
		For(&corev1.Pod{}).
		Complete(&reconiler)
}

func (r *RecorderReconciler) Reconcile(req reconcile.Request) (reconcile.Result, error) {
	logger := r.log.WithValues("recorder", req.Name, "namespace", req.Namespace)

	ctx, cancel := context.WithTimeout(context.Background(), reconcileTimeout)
	defer cancel()

	pod := &corev1.Pod{}
	if err := r.client.Get(ctx, req.NamespacedName, pod); err != nil {
		if kerrors.IsNotFound(err) {
			if err := r.collectProfile(ctx, req.NamespacedName); err != nil {
				return reconcile.Result{}, nil
			}
		} else {
			// Returning an error means we will be requeued implicitly.
			logger.Error(err, "Error reading pod")
			return reconcile.Result{}, errors.Wrap(err, errGetPod)
		}
	}

	logger.Info("RecorderReconciler", "pod status", pod.Status.Phase)

	if pod.Status.Phase == corev1.PodRunning || pod.Status.Phase == corev1.PodSucceeded {
		if r.podsToWatch[req.NamespacedName.String()] != "" {
			// We're tracking this pod already
			return reconcile.Result{}, nil
		}
		of, _, err := parseAnnotation(pod.Annotations[traceAnnotation])
		if err != nil {
			logger.Info("Unable to parse annoation. Ingoring", "error", err)
			return reconcile.Result{}, nil
		}
		if !strings.HasPrefix(of, config.SeccompHookOutputPath) {
			logger.Info("Ingoring Profile outside standard output path")
		}
		r.podsToWatch[req.NamespacedName.String()] = of
		r.record.Event(pod, event.Normal(reasonProfileRecording, "Recording seccomp profile"))
	}
	if pod.Status.Phase == corev1.PodSucceeded {
		if err := r.collectProfile(ctx, req.NamespacedName); err != nil {
			return reconcile.Result{}, nil
		}
	}

	for name, profile := range r.podsToWatch {
		logger.Info("RecorderReconciler", "Pod", name, "Profile", profile)
	}
	return reconcile.Result{}, nil
}

func (r *RecorderReconciler) collectProfile(ctx context.Context, name types.NamespacedName) error {
	profilePath := r.podsToWatch[name.String()]
	if profilePath == "" {
		// ignoring this error for now
		r.log.Info("Can not collect seccomp profile. Profile path empty")
		return nil
	}

	r.log.Info("collecting profile", "profile path", r.podsToWatch[name.String()])
	data, err := ioutil.ReadFile(profilePath)
	if err != nil {
		r.log.Error(err, "Failed to read profile")
		return err
	}

	profileName := strings.TrimSuffix(filepath.Base(profilePath), ".json")

	profile := &v1alpha1.SeccompProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      profileName,
			Namespace: name.Namespace,
		},
	}
	res, err := controllerutil.CreateOrUpdate(ctx, r.client, profile, func() error {
		err := json.Unmarshal(data, &profile.Spec)
		return err
	})
	if err != nil {
		r.log.Error(err, "cannot create seccompprofile resource")
		r.record.Event(profile, event.Warning(reasonProfileCreationFailed, err))
		return err
	}
	r.log.Info("Create or Update", "result", res)
	r.record.Event(profile, event.Normal(reasonProfileCreated, "seccomp profile created"))
	delete(r.podsToWatch, name.String())
	return nil
}

// Taken from the seccomp-bpf-hook sources
// parseAnnotation parses the provided annotation and extracts the mandatory
// output file and the optional input file (which is currently unused in the
// seccomp operator.
func parseAnnotation(annotation string) (outputFile, inputFile string, err error) {
	annotationSplit := strings.Split(annotation, ";")
	if len(annotationSplit) > maxTraceAnnotations {
		return "", "", errors.Wrapf(errors.New(errInvalidAnnotation),
			"more than one semi-colon: %q", annotation)
	}
	for _, path := range annotationSplit {
		switch {
		// Input profile
		case strings.HasPrefix(path, "if:"):
			inputFile = strings.TrimSpace(strings.TrimPrefix(path, "if:"))

		// Output profile
		case strings.HasPrefix(path, "of:"):
			outputFile = strings.TrimSpace(strings.TrimPrefix(path, "of:"))
			if !filepath.IsAbs(outputFile) {
				return "", "", errors.Wrapf(errors.New(errInvalidAnnotation),
					"output file path must be absolute: %q", outputFile)
			}
		// Unsupported default
		default:
			return "", "", errors.Wrapf(errors.New(errInvalidAnnotation),
				"must start %q or %q prefix", "of:", "if:")
		}
	}

	if outputFile == "" {
		return "", "", errors.Wrap(errors.New(errInvalidAnnotation),
			"providing output file is mandatory")
	}

	return outputFile, inputFile, nil
}
