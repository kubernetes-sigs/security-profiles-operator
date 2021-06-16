/*
Copyright 2019 The Crossplane Authors.

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

package resource

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/crossplane/crossplane-runtime/pkg/meta"
)

// A PredicateFn returns true if the supplied object should be reconciled.
type PredicateFn func(obj runtime.Object) bool

// NewPredicates returns a set of Funcs that are all satisfied by the supplied
// PredicateFn. The PredicateFn is run against the new object during updates.
func NewPredicates(fn PredicateFn) predicate.Funcs {
	return predicate.Funcs{
		CreateFunc:  func(e event.CreateEvent) bool { return fn(e.Object) },
		DeleteFunc:  func(e event.DeleteEvent) bool { return fn(e.Object) },
		UpdateFunc:  func(e event.UpdateEvent) bool { return fn(e.ObjectNew) },
		GenericFunc: func(e event.GenericEvent) bool { return fn(e.Object) },
	}
}

// AnyOf accepts objects that pass any of the supplied predicate functions.
func AnyOf(fn ...PredicateFn) PredicateFn {
	return func(obj runtime.Object) bool {
		for _, f := range fn {
			if f(obj) {
				return true
			}
		}
		return false
	}
}

// AllOf accepts objects that pass all of the supplied predicate functions.
func AllOf(fn ...PredicateFn) PredicateFn {
	return func(obj runtime.Object) bool {
		for _, f := range fn {
			if !f(obj) {
				return false
			}
		}
		return true
	}
}

// HasManagedResourceReferenceKind accepts objects that reference the supplied
// managed resource kind.
func HasManagedResourceReferenceKind(k ManagedKind) PredicateFn {
	return func(obj runtime.Object) bool {
		r, ok := obj.(ManagedResourceReferencer)
		if !ok {
			return false
		}

		if r.GetResourceReference() == nil {
			return false
		}

		return r.GetResourceReference().GroupVersionKind() == schema.GroupVersionKind(k)
	}
}

// IsManagedKind accepts objects that are of the supplied managed resource kind.
func IsManagedKind(k ManagedKind, ot runtime.ObjectTyper) PredicateFn {
	return func(obj runtime.Object) bool {
		gvk, err := GetKind(obj, ot)
		if err != nil {
			return false
		}
		return gvk == schema.GroupVersionKind(k)
	}
}

// IsControlledByKind accepts objects that are controlled by a resource of the
// supplied kind.
func IsControlledByKind(k schema.GroupVersionKind) PredicateFn {
	return func(obj runtime.Object) bool {
		mo, ok := obj.(metav1.Object)
		if !ok {
			return false
		}

		ref := metav1.GetControllerOf(mo)
		if ref == nil {
			return false
		}

		return ref.APIVersion == k.GroupVersion().String() && ref.Kind == k.Kind
	}
}

// IsPropagator accepts objects that request to be partially or fully propagated
// to another object of the same kind.
func IsPropagator() PredicateFn {
	return func(obj runtime.Object) bool {
		from, ok := obj.(metav1.Object)
		if !ok {
			return false
		}

		return len(meta.AllowsPropagationTo(from)) > 0
	}
}

// IsPropagated accepts objects that consent to be partially or fully propagated
// from another object of the same kind.
func IsPropagated() PredicateFn {
	return func(obj runtime.Object) bool {
		to, ok := obj.(metav1.Object)
		if !ok {
			return false
		}
		nn := meta.AllowsPropagationFrom(to)
		return nn.Namespace != "" && nn.Name != ""
	}
}

// IsNamed accepts objects that is named as the given name.
func IsNamed(name string) PredicateFn {
	return func(obj runtime.Object) bool {
		mo, ok := obj.(metav1.Object)
		if !ok {
			return false
		}
		return mo.GetName() == name
	}
}
