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

package nodestatus

import (
	"context"
	"os"

	"github.com/pkg/errors"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	secprofnodestatusv1alpha1 "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

type StatusClient struct {
	pol             client.Object
	nodeName        string
	finalizerString string
}

func NewForProfile(pol client.Object) (*StatusClient, error) {
	nodeName, ok := os.LookupEnv(config.NodeNameEnvKey)
	if !ok {
		return nil, errors.New("cannot determine node name")
	}
	return &StatusClient{
		pol:             pol,
		nodeName:        nodeName,
		finalizerString: nodeName + "-delete",
	}, nil
}

func (nsf *StatusClient) perNodeStatusName() string {
	return nsf.pol.GetName() + "-" + nsf.nodeName
}

func (nsf *StatusClient) perNodeStatusNamespacedName() types.NamespacedName {
	return util.NamespacedName(nsf.perNodeStatusName(), nsf.pol.GetNamespace())
}

func (nsf *StatusClient) Create(ctx context.Context, c client.Client) error {
	if err := nsf.createFinalizer(ctx, c); err != nil {
		return errors.Wrapf(err, "cannot create finalizer for %s", nsf.pol.GetName())
	}

	// if object does not exist, add it
	if err := nsf.createNodeStatus(ctx, c); err != nil {
		return errors.Wrapf(err, "cannot create node status for %s", nsf.pol.GetName())
	}
	return nil
}

func (nsf *StatusClient) createFinalizer(ctx context.Context, c client.Client) error {
	return util.Retry(func() error {
		return util.AddFinalizer(ctx, c, nsf.pol, nsf.finalizerString)
	}, util.IsNotFoundOrConflict)
}

func (nsf *StatusClient) statusObj(
	polState secprofnodestatusv1alpha1.ProfileState,
) *secprofnodestatusv1alpha1.SecurityProfileNodeStatus {
	return &secprofnodestatusv1alpha1.SecurityProfileNodeStatus{
		ObjectMeta: metav1.ObjectMeta{
			Name:      nsf.perNodeStatusName(),
			Namespace: nsf.pol.GetNamespace(),
			Labels: map[string]string{
				secprofnodestatusv1alpha1.StatusToProfLabel: nsf.pol.GetName(),
				secprofnodestatusv1alpha1.StatusToNodeLabel: nsf.nodeName,
				secprofnodestatusv1alpha1.StatusStateLabel:  string(polState),
				secprofnodestatusv1alpha1.StatusKindLabel:   nsf.pol.GetObjectKind().GroupVersionKind().Kind,
			},
		},
		NodeName: nsf.nodeName,
		Status:   polState,
	}
}

func (nsf *StatusClient) createNodeStatus(ctx context.Context, c client.Client) error {
	err := c.Create(ctx, nsf.statusObj(secprofnodestatusv1alpha1.ProfileStatePending))
	if err != nil && !kerrors.IsAlreadyExists(err) {
		return errors.Wrap(err, "creating node status")
	}

	return nil
}

func (nsf *StatusClient) Remove(ctx context.Context, c client.Client) error {
	// if object exists, remove it
	if err := nsf.removeNodeStatus(ctx, c); err != nil {
		return errors.Wrapf(err, "cannot create nodeStatus for %s", nsf.pol.GetName())
	}

	// if finalizer exists, remove it
	if err := nsf.removeFinalizer(ctx, c); err != nil {
		return errors.Wrapf(err, "cannot create finalizer for %s", nsf.pol.GetName())
	}

	return nil
}

func (nsf *StatusClient) removeFinalizer(ctx context.Context, c client.Client) error {
	return util.Retry(func() error {
		return util.RemoveFinalizer(ctx, c, nsf.pol, nsf.finalizerString)
	}, util.IsNotFoundOrConflict)
}

func (nsf *StatusClient) removeNodeStatus(ctx context.Context, c client.Client) error {
	// the state here is more or less unused, we just care about the name since we're deleting...
	err := c.Delete(ctx, nsf.statusObj(secprofnodestatusv1alpha1.ProfileStateTerminating))
	if err != nil && !kerrors.IsNotFound(err) {
		return errors.Wrap(err, "deleting node status")
	}

	return nil
}

func (nsf *StatusClient) Exists(ctx context.Context, c client.Client) (bool, error) {
	f := nsf.finalizerExists()
	s, err := nsf.nodeStatusExists(ctx, c)

	return s || f, err
}

func (nsf *StatusClient) finalizerExists() bool {
	return controllerutil.ContainsFinalizer(nsf.pol, nsf.finalizerString)
}

func (nsf *StatusClient) nodeStatusExists(ctx context.Context, c client.Client) (bool, error) {
	status := secprofnodestatusv1alpha1.SecurityProfileNodeStatus{}
	err := c.Get(ctx, nsf.perNodeStatusNamespacedName(), &status)
	if kerrors.IsNotFound(err) {
		return false, nil
	} else if err != nil {
		return false, errors.Wrap(err, "fetching node status")
	}

	return true, nil
}

func (nsf *StatusClient) SetReturnGlobal(
	ctx context.Context, c client.Client, polState secprofnodestatusv1alpha1.ProfileState,
) (secprofnodestatusv1alpha1.ProfileState, error) {
	if err := nsf.setNodeStatus(ctx, c, polState); err != nil {
		return secprofnodestatusv1alpha1.ProfileStateError, errors.Wrap(err, "setting node status")
	}

	// search all statuses
	statusList := secprofnodestatusv1alpha1.SecurityProfileNodeStatusList{}
	allStatusesForProf := client.MatchingLabels{
		secprofnodestatusv1alpha1.StatusToProfLabel: nsf.pol.GetName(),
	}
	if err := c.List(ctx, &statusList, allStatusesForProf); err != nil {
		return secprofnodestatusv1alpha1.ProfileStateError, errors.Wrap(err, "listing statuses")
	}

	// figure out the 'lowest common one'
	lowestCommonState := secprofnodestatusv1alpha1.ProfileStateTerminating
	for i := range statusList.Items {
		lowestCommonState = secprofnodestatusv1alpha1.LowerOfTwoStates(lowestCommonState, statusList.Items[i].Status)
	}

	// TODO(jhrozek): It would be nicer to come up with an interface the consumer would assign so that
	// instead of returning a state we could just call that method to do the work..

	// return the global status to the caller so that they can set it
	return lowestCommonState, nil
}

func (nsf *StatusClient) setNodeStatus(
	ctx context.Context, c client.Client, polState secprofnodestatusv1alpha1.ProfileState,
) error {
	status := secprofnodestatusv1alpha1.SecurityProfileNodeStatus{}
	err := c.Get(ctx, nsf.perNodeStatusNamespacedName(), &status)
	if kerrors.IsNotFound(err) && polState == secprofnodestatusv1alpha1.ProfileStateTerminating {
		// it's OK if we're about to terminate a profile but it was already gone
		return nil
	} else if err != nil {
		return errors.Wrap(err, "retrieving the current status")
	}

	status.Status = polState
	status.Labels[secprofnodestatusv1alpha1.StatusStateLabel] = string(polState)
	if err := c.Update(ctx, &status); err != nil {
		return errors.Wrap(err, "updating node status")
	}

	return nil
}
