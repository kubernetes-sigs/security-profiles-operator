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

package e2e_test

import (
	"fmt"
	"path"
	"time"

	secprofnodestatusv1alpha1 "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1alpha1"
	spodv1alpha1 "sigs.k8s.io/security-profiles-operator/api/spod/v1alpha1"
)

func (e *e2e) testCaseDeleteProfiles(nodes []string) {
	e.seccompOnlyTestCase()
	const (
		deleteProfile = `
apiVersion: security-profiles-operator.x-k8s.io/v1beta1
kind: SeccompProfile
metadata:
  name: delete-me
  finalizers: [fake-node-deleted]
spec:
  defaultAction: "SCMP_ACT_ALLOW"
`
		deleteProfileName  = "delete-me"
		fakeNodeStatusName = "delete-me-fake-node"
		fakeNodeStatus     = `
apiVersion: security-profiles-operator.x-k8s.io/v1alpha1
kind: SecurityProfileNodeStatus
metadata:
  name: delete-me-fake-node
  labels:
    spo.x-k8s.io/node-name: fake-node
    spo.x-k8s.io/profile-id: SeccompProfile-delete-me
    spo.x-k8s.io/profile-kind: SeccompProfile
    spo.x-k8s.io/profile-state: Installed
nodeName: fake-node
spec: {}
status: Installed
`
		deletePod = `
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
  - name: test-container
    image: quay.io/security-profiles-operator/test-nginx-unprivileged:1.21
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: operator/%s/delete-me.json
`
		deletePodSecurityContextInContainer = `
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
  - name: test-container
    image: quay.io/security-profiles-operator/test-nginx-unprivileged:1.21
    securityContext:
      seccompProfile:
        type: Localhost
        localhostProfile: operator/%s/delete-me.json
`
		deletePodSecurityContextInInitContainer = `
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  initContainers:
  - name: init-container
    image: registry.fedoraproject.org/fedora-minimal:latest
    securityContext:
      seccompProfile:
        type: Localhost
        localhostProfile: operator/%s/delete-me.json
  containers:
  - name: test-container
    image: quay.io/security-profiles-operator/test-nginx-unprivileged:1.21
`
		deletePodSecurityContextInAnnotation = `
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  annotations:
    seccomp.security.alpha.kubernetes.io/pod: 'localhost/operator/%s/delete-me.json'
spec:
  containers:
  - name: test-container
    image: quay.io/security-profiles-operator/test-nginx-unprivileged:1.21
`
		deletePodName = "test-pod"
	)

	profileCleanup := e.writeAndCreate(deleteProfile, "delete-profile*.yaml")
	defer profileCleanup()

	namespace := e.getCurrentContextNamespace(defaultNamespace)
	sp := e.getSeccompProfile(deleteProfileName, namespace)
	profileOperatorPath := path.Join(e.nodeRootfsPrefix, sp.GetProfileOperatorPath())

	e.logf("Waiting for profile to be reconciled")
	e.waitFor("condition=ready", "seccompprofile", deleteProfileName)

	e.logf("Verifying profile exists")
	time.Sleep(time.Second)
	for _, node := range nodes {
		e.execNode(node, "test", "-f", profileOperatorPath)
	}
	e.logf("Create fake node status for profile")
	e.writeAndCreate(fakeNodeStatus, "fake-node-status*.yaml")
	time.Sleep(time.Second)
	e.logf("Verifying profile deleted")
	e.kubectl("delete", "seccompprofile", deleteProfileName)
	time.Sleep(time.Second)
	for _, node := range nodes {
		e.execNode(node, "test", "!", "-f", profileOperatorPath)
	}

	// Check linking pods prevent deletion
	for _, testCase := range []struct {
		description string
		podManifest string
	}{
		{
			"pod with security context for pod",
			deletePod,
		},
		{
			"pod with security context for container",
			deletePodSecurityContextInContainer,
		},
		{
			"pod with security context in init container",
			deletePodSecurityContextInInitContainer,
		},
		{
			"pod with security context in annotation",
			deletePodSecurityContextInAnnotation,
		},
	} {
		e.logf("> > Running test case for deleted profiles and pods: %s", testCase.description)
		profileCleanup := e.writeAndCreate(deleteProfile, "delete-profile*.yaml")
		defer profileCleanup() //nolint:gocritic // TODO: is this intentional?
		e.waitFor("condition=ready", "seccompprofile", deleteProfileName)
		e.logf("Create fake node status for profile")
		e.writeAndCreate(fakeNodeStatus, "fake-node-status*.yaml")
		podCleanup := e.writeAndCreate(fmt.Sprintf(testCase.podManifest, namespace), "delete-pod*.yaml")
		defer podCleanup() //nolint:gocritic // TODO: is this intention?
		e.waitFor("condition=ready", "pod", deletePodName)
		e.logf("Ensuring profile cannot be deleted while pod is active")
		e.kubectl("delete", "seccompprofile", deleteProfileName, "--wait=0")

		e.logf("Waiting for profile to be marked as terminating but not deleted")
		// TODO(jhrozek): deleting manifests as Ready=False, reason=Deleting, can we wait in a nicer way?
		for i := 0; i < 10; i++ {
			sp := e.getSeccompProfile(deleteProfileName, namespace)
			conReady := sp.Status.GetReadyCondition()
			if conReady.Reason == spodv1alpha1.ReasonDeleting {
				break
			}
			time.Sleep(time.Second)
		}

		// At this point it must be terminating or else we haven't matched the condition above
		sp := e.getSeccompProfile(deleteProfileName, namespace)
		e.Equal(sp.Status.Status, secprofnodestatusv1alpha1.ProfileStateTerminating)

		// The node statuses should still be there, just terminating
		nodeStatuses := e.getAllSeccompProfileNodeStatuses(deleteProfileName, namespace)
		for i := range nodeStatuses.Items {
			e.Equal(nodeStatuses.Items[i].Status, secprofnodestatusv1alpha1.ProfileStateTerminating)
			// On each node, there should still be the profile on the disk
			nodeWithPodName := nodeStatuses.Items[i].NodeName
			profileOperatorPath := path.Join(e.nodeRootfsPrefix, sp.GetProfileOperatorPath())
			e.execNode(nodeWithPodName, "test", "-f", profileOperatorPath)
		}

		isDeleted := make(chan bool)
		go func() {
			e.waitFor("delete", "seccompprofile", deleteProfileName)
			isDeleted <- true
		}()

		e.kubectl("delete", "pod", deletePodName)

		// Wait a bit for the seccompprofile to be actually deleted
		<-isDeleted
	}
}
