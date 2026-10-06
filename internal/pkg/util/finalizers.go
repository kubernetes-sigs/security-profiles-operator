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

package util

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// AddFinalizer attempts to add a finalizer to an object if not present and update the object.
// It fetches the object into pol first, so pol holds the stored object
// afterwards and any unsaved change of the caller is lost.
func AddFinalizer(ctx context.Context, c client.Client, pol client.Object, finalizer string) error {
	if err := c.Get(ctx, NamespacedName(pol.GetName(), pol.GetNamespace()), pol); err != nil {
		return fmt.Errorf("%s: %w", ErrGetProfile, err)
	}

	if controllerutil.ContainsFinalizer(pol, finalizer) {
		return nil
	}

	controllerutil.AddFinalizer(pol, finalizer)

	return c.Update(ctx, pol)
}

// RemoveFinalizer attempts to remove a finalizer from an object if present and update the object.
// Like AddFinalizer, it overwrites pol with the stored object.
func RemoveFinalizer(
	ctx context.Context,
	c client.Client,
	pol client.Object,
	finalizer string,
) error {
	return RemoveFinalizers(ctx, c, pol, finalizer)
}

// RemoveFinalizers removes every one of the provided finalizers which the
// object carries with a single update. Empty finalizers are ignored. Like
// AddFinalizer, it overwrites pol with the stored object.
func RemoveFinalizers(
	ctx context.Context,
	c client.Client,
	pol client.Object,
	finalizers ...string,
) error {
	if err := c.Get(ctx, NamespacedName(pol.GetName(), pol.GetNamespace()), pol); err != nil {
		return fmt.Errorf("%s: %w", ErrGetProfile, err)
	}

	removed := false

	for _, finalizer := range finalizers {
		if finalizer != "" && controllerutil.RemoveFinalizer(pol, finalizer) {
			removed = true
		}
	}

	if !removed {
		return nil
	}

	return c.Update(ctx, pol)
}

const (
	// nodeFinalizerSuffix ends the finalizer which a node adds to a profile.
	nodeFinalizerSuffix = "-deleted"

	// nodeFinalizerHashPrefixLen is how many characters of a long node name
	// are kept in front of its hash, so that the finalizer still hints at the
	// node.
	nodeFinalizerHashPrefixLen = 16
)

// nodeNameFits returns true if the finalizer of the node fits into the length
// limit of a finalizer without shortening the node name.
func nodeNameFits(nodeName string) bool {
	return len(nodeName)+len(nodeFinalizerSuffix) <= validation.DNS1123LabelMaxLength
}

// GetFinalizerNodeString returns the finalizer which the daemon of the node
// adds to a profile. A node name which does not fit is shortened by hashing
// it, so that two nodes whose names only differ past the cut do not share a
// finalizer: the first of them finishing a deletion would otherwise remove the
// finalizer of the other one. The suffix is kept, because the manager
// recognizes node finalizers by it.
func GetFinalizerNodeString(nodeName string) string {
	if nodeNameFits(nodeName) {
		return nodeName + nodeFinalizerSuffix
	}

	hashed, err := hashedName(
		validation.DNS1123LabelMaxLength-len(nodeFinalizerSuffix),
		nodeName[:nodeFinalizerHashPrefixLen],
		nodeName,
	)
	if err != nil {
		// Cannot happen: the prefix leaves room for the hash.
		return GetLegacyFinalizerNodeString(nodeName)
	}

	return hashed + nodeFinalizerSuffix
}

// GetLegacyFinalizerNodeString returns the finalizer which earlier releases
// added for a node whose name does not fit into a finalizer: the name got
// truncated, which merged the finalizers of nodes with a long common prefix.
// Profiles created before the upgrade still carry it. A node adds its current
// finalizer next to it, but keeps it, because the other nodes sharing it may
// not have added theirs yet. It is removed along with the current one when the
// node removes the profile. It is empty if the node name fits, because then
// the finalizer never changed.
func GetLegacyFinalizerNodeString(nodeName string) string {
	if nodeNameFits(nodeName) {
		return ""
	}

	return nodeName[:validation.DNS1123LabelMaxLength-len(nodeFinalizerSuffix)] + nodeFinalizerSuffix
}
