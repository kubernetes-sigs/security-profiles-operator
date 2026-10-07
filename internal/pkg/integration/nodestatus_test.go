//go:build integration

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

package integration

import (
	"testing"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"sigs.k8s.io/security-profiles-operator/api/common"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	secprofnodestatusapi "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/nodestatus"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

// createReadySpod creates the SPOd DaemonSet in the operator namespace with a
// status which reports the provided number of nodes as ready.
func createReadySpod(t *testing.T, nodes int32) {
	t.Helper()

	labels := map[string]string{"name": "spod"}
	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: "spod", Namespace: operatorNamespace},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "spod", Image: "registry.k8s.io/pause:3.10"},
					},
				},
			},
		},
	}
	// A repeated run of the test finds the DaemonSet of the first run.
	if err := k8sClient.Create(t.Context(), ds); apierrors.IsAlreadyExists(err) {
		require.NoError(t, k8sClient.Get(t.Context(), client.ObjectKeyFromObject(ds), ds))
	} else {
		require.NoError(t, err)
	}

	// Without the DaemonSet controller, the status is whatever the test sets.
	ds.Status = appsv1.DaemonSetStatus{
		CurrentNumberScheduled: nodes,
		DesiredNumberScheduled: nodes,
		NumberReady:            nodes,
		NumberAvailable:        nodes,
		UpdatedNumberScheduled: nodes,
		ObservedGeneration:     ds.Generation,
	}
	require.NoError(t, k8sClient.Status().Update(t.Context(), ds))
}

// createNode creates a node, which the node statuses refer to. A status of a
// node which does not exist is one of a deleted node, which the profile does
// not count.
func createNode(t *testing.T, name string) {
	t.Helper()

	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name}}
	// A repeated run of the test finds the node of the first run.
	if err := k8sClient.Create(t.Context(), node); !apierrors.IsAlreadyExists(err) {
		require.NoError(t, err)
	}
}

// createNodeStatus creates the status of the profile on the node, like the
// daemon of the node does, and sets its state.
func createNodeStatus(
	t *testing.T,
	profile *seccompprofileapi.SeccompProfile,
	node string,
	state secprofnodestatusapi.ProfileState,
) *secprofnodestatusapi.SecurityProfileNodeStatus {
	t.Helper()

	const kind = "SeccompProfile"

	status := &secprofnodestatusapi.SecurityProfileNodeStatus{
		ObjectMeta: metav1.ObjectMeta{
			Name: profile.Name + "-" + node,
			Labels: map[string]string{
				secprofnodestatusapi.StatusToProfLabel: util.KindNameDNSLengthName(
					kind,
					profile.Name,
				),
				secprofnodestatusapi.StatusToNodeLabel: node,
				secprofnodestatusapi.StatusKindLabel:   kind,
			},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion:         seccompprofileapi.GroupVersion.String(),
				Kind:               kind,
				Name:               profile.Name,
				UID:                profile.UID,
				Controller:         new(true),
				BlockOwnerDeletion: new(true),
			}},
		},
		Spec: secprofnodestatusapi.SecurityProfileNodeStatusSpec{NodeName: node},
	}
	require.NoError(t, k8sClient.Create(t.Context(), status))

	setNodeStatus(t, status, state)

	return status
}

// setNodeStatus sets the state of the node status.
func setNodeStatus(
	t *testing.T,
	status *secprofnodestatusapi.SecurityProfileNodeStatus,
	state secprofnodestatusapi.ProfileState,
) {
	t.Helper()

	status.Status.Status = state
	require.NoError(t, k8sClient.Status().Update(t.Context(), status))
}

// requireProfileState waits until the profile reports the state with the
// provided Ready condition.
func requireProfileState(
	t *testing.T,
	profile *seccompprofileapi.SeccompProfile,
	state secprofnodestatusapi.ProfileState,
	ready metav1.ConditionStatus,
) {
	t.Helper()

	eventuallyGet(t, client.ObjectKeyFromObject(profile), &seccompprofileapi.SeccompProfile{},
		func(sp *seccompprofileapi.SeccompProfile) bool {
			condition := sp.Status.GetReadyCondition()

			return sp.Status.Status == state &&
				condition.Type == string(common.TypeReady) &&
				condition.Status == ready &&
				condition.ObservedGeneration == sp.Generation
		},
		"waiting for SeccompProfile "+profile.Name+" to become "+string(state),
	)
}

func TestNodeStatusAggregatesIntoProfile(t *testing.T) {
	t.Parallel()
	requireEnv(t)

	// The node status controller takes the operator namespace from the
	// environment, so this is the only test using it.
	createReadySpod(t, 2)

	// The node statuses and profiles are cluster scoped, only the SPOd
	// DaemonSet is namespaced.
	startManager(
		t,
		nodestatus.NewController(),
		managerOptions{namespaces: []string{operatorNamespace}},
	)

	profile := &seccompprofileapi.SeccompProfile{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "aggregated-"},
		Spec:       seccompprofileapi.SeccompProfileSpec{DefaultAction: seccompprofileapi.ActAllow},
	}
	require.NoError(t, k8sClient.Create(t.Context(), profile))

	createNode(t, "node-1")
	createNode(t, "node-2")

	// The first status initializes the status of the profile.
	node1 := createNodeStatus(t, profile, "node-1", secprofnodestatusapi.ProfileStateInstalled)
	eventuallyGet(t, client.ObjectKeyFromObject(profile), &seccompprofileapi.SeccompProfile{},
		func(sp *seccompprofileapi.SeccompProfile) bool { return sp.Status.Status != "" },
		"waiting for the initial profile status",
	)

	// The profile reports the lowest state of all nodes once every node of
	// the SPOd reported a status.
	node2 := createNodeStatus(t, profile, "node-2", secprofnodestatusapi.ProfileStateError)
	requireProfileState(t, profile, secprofnodestatusapi.ProfileStateError, metav1.ConditionFalse)

	setNodeStatus(t, node2, secprofnodestatusapi.ProfileStateInstalled)
	requireProfileState(
		t,
		profile,
		secprofnodestatusapi.ProfileStateInstalled,
		metav1.ConditionTrue,
	)

	// A node which starts removing the profile turns it terminating.
	require.NoError(t, k8sClient.Get(t.Context(), client.ObjectKeyFromObject(node1), node1))
	setNodeStatus(t, node1, secprofnodestatusapi.ProfileStateTerminating)
	requireProfileState(
		t,
		profile,
		secprofnodestatusapi.ProfileStateTerminating,
		metav1.ConditionFalse,
	)
}
