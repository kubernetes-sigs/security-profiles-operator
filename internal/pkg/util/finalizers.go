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
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// AddFinalizer adds the finalizer to the object if it is missing, see
// AddFinalizerAndLabel.
func AddFinalizer(ctx context.Context, c client.Client, pol client.Object, finalizer string) error {
	return AddFinalizerAndLabel(ctx, c, pol, finalizer, "", "")
}

// AddFinalizerAndLabel adds the finalizer and the label to the object with a
// single patch, unless the object has them already. A present label keeps its
// value, and an empty label key adds no label. It fetches the object into pol
// first, so pol holds the stored object afterwards and any unsaved change of
// the caller is lost.
//
// Many writers, like the daemons of all nodes, add their finalizers to the
// same object at once. The finalizer gets appended by a JSON patch, which the
// API server applies to the stored object, so it neither conflicts with nor
// drops the finalizers which others add in the meantime. A JSON patch cannot
// append to a list or add to a map which the object does not have, so an
// object without finalizers or labels gets a merge patch. It replaces the
// whole list of finalizers, so it carries the resource version if it adds the
// finalizer: a concurrent write fails it with a conflict instead of getting
// lost, and the retry of the caller appends. The labels are merged.
//
// An outdated read can make the object carry the finalizer twice, which is
// harmless: RemoveFinalizers removes every occurrence.
func AddFinalizerAndLabel(
	ctx context.Context, c client.Client, pol client.Object, finalizer, labelKey, labelValue string,
) error {
	if err := c.Get(ctx, NamespacedName(pol.GetName(), pol.GetNamespace()), pol); err != nil {
		return fmt.Errorf("%s: %w", ErrGetProfile, err)
	}

	addFinalizer := !controllerutil.ContainsFinalizer(pol, finalizer)

	_, hasLabel := pol.GetLabels()[labelKey]
	addLabel := labelKey != "" && !hasLabel

	if !addFinalizer && !addLabel {
		return nil
	}

	if (addFinalizer && len(pol.GetFinalizers()) == 0) || (addLabel && len(pol.GetLabels()) == 0) {
		return mergeFinalizerAndLabel(
			ctx, c, pol, addFinalizer, finalizer, addLabel, labelKey, labelValue,
		)
	}

	var ops []jsonPatchOp

	if addLabel {
		ops = append(ops, jsonPatchOp{
			Op: "add", Path: "/metadata/labels/" + escapeJSONPointer(labelKey), Value: labelValue,
		})
	}

	if addFinalizer {
		ops = append(ops, jsonPatchOp{Op: "add", Path: "/metadata/finalizers/-", Value: finalizer})
	}

	return patchJSON(ctx, c, pol, ops)
}

// mergeFinalizerAndLabel adds the finalizer and the label with a merge patch.
// A patch which adds the finalizer fails with a conflict if the object changed
// since it was read.
func mergeFinalizerAndLabel(
	ctx context.Context,
	c client.Client,
	pol client.Object,
	addFinalizer bool,
	finalizer string,
	addLabel bool,
	labelKey, labelValue string,
) error {
	base, ok := pol.DeepCopyObject().(client.Object)
	if !ok {
		return fmt.Errorf("copying %s: unexpected type %T", pol.GetName(), pol)
	}

	if addFinalizer {
		controllerutil.AddFinalizer(pol, finalizer)
	}

	if addLabel {
		labels := pol.GetLabels()
		if labels == nil {
			labels = map[string]string{}
		}

		labels[labelKey] = labelValue
		pol.SetLabels(labels)
	}

	if !addFinalizer {
		return c.Patch(ctx, pol, client.MergeFrom(base))
	}

	return c.Patch(
		ctx,
		pol,
		client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{}),
	)
}

// RemoveFinalizer removes the finalizer from the object if present, see
// RemoveFinalizers.
func RemoveFinalizer(
	ctx context.Context,
	c client.Client,
	pol client.Object,
	finalizer string,
) error {
	return RemoveFinalizers(ctx, c, pol, finalizer)
}

// RemoveFinalizers removes every occurrence of the provided finalizers from
// the object with a single JSON patch. Empty finalizers are ignored. Like
// AddFinalizerAndLabel, it overwrites pol with the stored object.
//
// Each removal tests that the finalizer is still at the index where pol has
// it, so the patch cannot remove the finalizer of another writer. Finalizers
// appended in the meantime and changes to the rest of the object do not fail
// the patch, unlike a resource version would. If the finalizers moved, the
// patch fails with a conflict, which the caller retries.
func RemoveFinalizers(
	ctx context.Context,
	c client.Client,
	pol client.Object,
	finalizers ...string,
) error {
	if err := c.Get(ctx, NamespacedName(pol.GetName(), pol.GetNamespace()), pol); err != nil {
		return fmt.Errorf("%s: %w", ErrGetProfile, err)
	}

	var ops []jsonPatchOp

	// Removing from the end keeps the indexes of the earlier ones.
	for i, finalizer := range slices.Backward(pol.GetFinalizers()) {
		if finalizer == "" || !slices.Contains(finalizers, finalizer) {
			continue
		}

		path := "/metadata/finalizers/" + strconv.Itoa(i)
		ops = append(ops,
			jsonPatchOp{Op: "test", Path: path, Value: finalizer},
			jsonPatchOp{Op: "remove", Path: path},
		)
	}

	if len(ops) == 0 {
		return nil
	}

	return patchJSON(ctx, c, pol, ops)
}

// jsonPatchOp is an operation of a JSON patch, see RFC 6902.
type jsonPatchOp struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value,omitempty"`
}

// escapeJSONPointer escapes a key for a JSON pointer, see RFC 6901.
func escapeJSONPointer(key string) string {
	return strings.NewReplacer("~", "~0", "/", "~1").Replace(key)
}

// patchJSON applies the JSON patch to the object. The API server rejects a
// JSON patch which does not apply to the stored object, because a test failed
// or a path is missing. The object changed since it was read then, so this is
// returned as a conflict, which the callers retry.
func patchJSON(ctx context.Context, c client.Client, obj client.Object, ops []jsonPatchOp) error {
	data, err := json.Marshal(ops)
	if err != nil {
		return fmt.Errorf("encoding the patch: %w", err)
	}

	err = c.Patch(ctx, obj, client.RawPatch(types.JSONPatchType, data))
	if patchDidNotApply(err) {
		resource := schema.GroupResource{}
		if gvk, gvkErr := c.GroupVersionKindFor(obj); gvkErr == nil {
			resource = schema.GroupResource{Group: gvk.Group, Resource: strings.ToLower(gvk.Kind)}
		}

		return kerrors.NewConflict(resource, obj.GetName(), err)
	}

	return err
}

// patchDidNotApply returns true if the API server rejected a JSON patch
// because it does not apply to the stored object. The API server reports this
// as invalid, but without the causes of a failed validation.
func patchDidNotApply(err error) bool {
	if !kerrors.IsInvalid(err) {
		return false
	}

	status, ok := errors.AsType[*kerrors.StatusError](err)
	if !ok {
		return false
	}

	details := status.Status().Details

	return details == nil || len(details.Causes) == 0
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
