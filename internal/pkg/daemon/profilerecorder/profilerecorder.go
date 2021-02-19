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

	"sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

const (
	// default reconcile timeout.
	reconcileTimeout = 1 * time.Minute

	errGetClient         = "cannot get client connection"
	errGetNode           = "cannot get node object"
	errGetPod            = "cannot get pod"
	errInvalidAnnotation = "invalid Annotation"

	reasonProfileRecording      event.Reason = "SeccompProfileRecording"
	reasonProfileCreated        event.Reason = "SeccompProfileCreated"
	reasonProfileCreationFailed event.Reason = "CannotCreateSeccompProfile"
	reasonAnnotationParsing     event.Reason = "SeccompAnnotationParsing"
)

type RecorderReconciler struct {
	client        client.Client
	log           logr.Logger
	record        event.Recorder
	nodeAddresses []string
	podsToWatch   map[string]string
}

// +kubebuilder:rbac:groups=core,resources=nodes,verbs=get;list;watch

func Setup(ctx context.Context, mgr ctrl.Manager, l logr.Logger) error {
	const name = "profilerecorder"
	c, err := client.New(mgr.GetConfig(), client.Options{})
	if err != nil {
		return errors.Wrap(err, errGetClient)
	}

	node := &corev1.Node{}
	if c.Get(
		context.Background(),
		client.ObjectKey{Name: os.Getenv(config.NodeNameEnvKey)},
		node,
	) != nil {
		return errors.Wrap(err, errGetNode)
	}

	nodeAddresses := []string{}
	for _, addr := range node.Status.Addresses {
		if addr.Type == corev1.NodeInternalIP {
			l.Info("Setting up profile recorder", "Node", addr.Address)
			nodeAddresses = append(nodeAddresses, addr.Address)
			break
		}
	}

	if len(nodeAddresses) == 0 {
		return errors.New("Unable to get node's internal Address")
	}

	reconciler := RecorderReconciler{
		client:        mgr.GetClient(),
		log:           l,
		nodeAddresses: nodeAddresses,
		record:        event.NewAPIRecorder(mgr.GetEventRecorderFor(name)),
		podsToWatch:   map[string]string{},
	}

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithEventFilter(predicate.And(
			resource.NewPredicates(reconciler.isPodWithTraceAnnotation),
			resource.NewPredicates(reconciler.isPodOnLocalNode),
		)).
		For(&corev1.Pod{}).
		Complete(&reconciler)
}

func (r *RecorderReconciler) isPodOnLocalNode(obj runtime.Object) bool {
	p, ok := obj.(*corev1.Pod)

	if !ok {
		return false
	}

	for _, addr := range r.nodeAddresses {
		if p.Status.HostIP == addr {
			return true
		}
	}

	return false
}

func (r *RecorderReconciler) isPodWithTraceAnnotation(obj runtime.Object) bool {
	p, ok := obj.(*corev1.Pod)

	if !ok {
		return false
	}

	return p.Annotations[config.SeccompProfileRecordAnnotationKey] != ""
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

	if pod.Status.Phase == corev1.PodPending {
		if r.podsToWatch[req.NamespacedName.String()] != "" {
			// We're tracking this pod already
			return reconcile.Result{}, nil
		}
		outputFile, err := parseAnnotation(pod.Annotations[config.SeccompProfileRecordAnnotationKey])
		if err != nil {
			// Malformed annotations could be set by users directly, which is
			// why we are ignoring them.
			logger.Info("Ignoring because unable to parse annotation", "error", err)
			r.record.Event(pod, event.Warning(reasonAnnotationParsing, err))
			return reconcile.Result{}, nil
		}
		if !strings.HasPrefix(outputFile, config.ProfileRecordingOutputPath) {
			logger.Info("Ignoring profile outside standard output path")
			return reconcile.Result{}, nil
		}

		logger.Info("Recording seccomp profile", "path", outputFile, "pod", pod.Name)
		r.podsToWatch[req.NamespacedName.String()] = outputFile
		r.record.Event(pod, event.Normal(reasonProfileRecording, "Recording seccomp profile"))
	}

	if pod.Status.Phase == corev1.PodSucceeded {
		if err := r.collectProfile(ctx, req.NamespacedName); err != nil {
			return reconcile.Result{}, nil
		}
	}

	return reconcile.Result{}, nil
}

func (r *RecorderReconciler) collectProfile(ctx context.Context, name types.NamespacedName) error {
	profilePath := r.podsToWatch[name.String()]
	if profilePath == "" {
		// ignoring this error for now
		return nil
	}

	r.log.Info("Collecting profile", "path", r.podsToWatch[name.String()])
	defer delete(r.podsToWatch, name.String())
	data, err := ioutil.ReadFile(profilePath)
	if err != nil {
		r.log.Error(err, "Failed to read profile")
		return errors.Wrap(err, "read profile")
	}

	// Remove the file extension and timestamp
	base := filepath.Base(profilePath)
	lastIndex := strings.LastIndex(base, "-")
	if lastIndex == -1 {
		return errors.Errorf("malformed profile path: %s", profilePath)
	}
	profileName := base[:lastIndex]

	profile := &v1alpha1.SeccompProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      profileName,
			Namespace: name.Namespace,
		},
	}
	res, err := controllerutil.CreateOrUpdate(ctx, r.client, profile, func() error {
		err := json.Unmarshal(data, &profile.Spec)
		return errors.Wrap(err, "unmarshal profile spec JSON")
	})
	if err != nil {
		r.log.Error(err, "cannot create seccompprofile resource")
		r.record.Event(profile, event.Warning(reasonProfileCreationFailed, err))
		return errors.Wrap(err, "create seccompProfile resource")
	}
	r.log.Info("Created/updated profile", "action", res, "name", profileName)
	r.record.Event(profile, event.Normal(reasonProfileCreated, "seccomp profile created"))
	return nil
}

// parseAnnotation parses the provided annotation and extracts the mandatory
// output file.
func parseAnnotation(annotation string) (string, error) {
	const prefix = "of:"

	if !strings.HasPrefix(annotation, prefix) {
		return "", errors.Wrapf(errors.New(errInvalidAnnotation),
			"must start with %q prefix", prefix)
	}

	outputFile := strings.TrimSpace(strings.TrimPrefix(annotation, prefix))
	if !filepath.IsAbs(outputFile) {
		return "", errors.Wrapf(errors.New(errInvalidAnnotation),
			"output file path must be absolute: %q", outputFile)
	}

	if outputFile == "" {
		return "", errors.Wrap(errors.New(errInvalidAnnotation),
			"providing output file is mandatory")
	}

	return outputFile, nil
}
