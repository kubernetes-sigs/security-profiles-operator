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

package bindata

import (
	"context"
	"fmt"
	"maps"
	"slices"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// UpdateService writes what the operator configures of the service: its
// type, its ports, its selector, its labels and annotations, and its owner
// references if it has any. It creates the service if it does not exist. A
// changed type, selector or target port keeps the API server or Prometheus
// from reaching the pods behind the service. A JSON merge patch of the
// configured service would keep selector keys which got added to the found
// one, so the patch is the difference to the found service instead, which
// is not sent if there is none. Labels and annotations which others added
// are kept.
func UpdateService(
	ctx context.Context, c client.Client, log logr.Logger, configured *corev1.Service,
) error {
	found := &corev1.Service{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(configured), found); err != nil {
		if errors.IsNotFound(err) {
			log.Info("Creating service", "service", configured.Name)

			return createOrConflict(ctx, c, configured.DeepCopy(), corev1.Resource("services"))
		}

		return fmt.Errorf("getting service: %w", err)
	}

	updated := found.DeepCopy()
	if serviceType(updated) != serviceType(configured) {
		// The fields of the other types would not validate with the
		// configured one.
		updated.Spec.ExternalTrafficPolicy = ""
		updated.Spec.HealthCheckNodePort = 0
		updated.Spec.AllocateLoadBalancerNodePorts = nil
		updated.Spec.LoadBalancerClass = nil
		updated.Spec.LoadBalancerSourceRanges = nil
	}

	// The API server rejects the annotation of the source ranges on a
	// service which is no load balancer, like the field.
	if serviceType(configured) != corev1.ServiceTypeLoadBalancer {
		delete(updated.Annotations, corev1.AnnotationLoadBalancerSourceRangesKey)
	}

	updated.Spec.Type = serviceType(configured)
	updated.Spec.ExternalName = configured.Spec.ExternalName
	updated.Spec.Ports = defaultedPorts(configured.Spec.Ports)
	updated.Spec.Selector = maps.Clone(configured.Spec.Selector)

	if len(configured.Labels) > 0 && updated.Labels == nil {
		updated.Labels = map[string]string{}
	}

	maps.Copy(updated.Labels, configured.Labels)

	if len(configured.Annotations) > 0 && updated.Annotations == nil {
		updated.Annotations = map[string]string{}
	}

	maps.Copy(updated.Annotations, configured.Annotations)

	if len(configured.OwnerReferences) > 0 {
		updated.OwnerReferences = slices.Clone(configured.OwnerReferences)
	}

	patch := client.MergeFrom(found)

	data, err := patch.Data(updated)
	if err != nil {
		return fmt.Errorf("computing the patch of the service: %w", err)
	}

	if string(data) == "{}" {
		return nil
	}

	log.Info("Restoring service", "service", configured.Name)

	if err := c.Patch(ctx, updated, patch); err != nil {
		return fmt.Errorf("patching service: %w", err)
	}

	return nil
}

// serviceType returns the type of the service, which the API server
// defaults to ClusterIP.
func serviceType(service *corev1.Service) corev1.ServiceType {
	if service.Spec.Type == "" {
		return corev1.ServiceTypeClusterIP
	}

	return service.Spec.Type
}

// defaultedPorts returns the ports with the defaults the API server sets: the
// protocol TCP, and the port as target port. A port without them would
// differ from the found one, and every update would patch the ports.
func defaultedPorts(ports []corev1.ServicePort) []corev1.ServicePort {
	defaulted := slices.Clone(ports)

	for i := range defaulted {
		port := &defaulted[i]
		if port.Protocol == "" {
			port.Protocol = corev1.ProtocolTCP
		}

		if port.TargetPort == (intstr.IntOrString{}) {
			port.TargetPort = intstr.FromInt32(port.Port)
		}
	}

	return defaulted
}

// createOrConflict creates the object which the cache does not know. The
// cache can be behind the API server, like right after the creation of the
// SPOD created the object, which then already exists. That is a conflict,
// which the reconciliation retries once the cache caught up.
func createOrConflict(
	ctx context.Context, c client.Client, obj client.Object, resource schema.GroupResource,
) error {
	err := c.Create(ctx, obj)
	if errors.IsAlreadyExists(err) {
		return errors.NewConflict(resource, obj.GetName(), err)
	}

	return err
}
