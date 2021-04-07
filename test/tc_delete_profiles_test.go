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
	"time"

	v1 "github.com/crossplane/crossplane-runtime/apis/common/v1"

	secprofnodestatusv1alpha1 "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1alpha1"
)

func (e *e2e) testCaseDeleteProfiles(nodes []string) {
	e.seccompOnlyTestCase()
	const (
		deleteProfile = `
apiVersion: security-profiles-operator.x-k8s.io/v1alpha1
kind: SeccompProfile
metadata:
  name: delete-me
spec:
  defaultAction: "SCMP_ACT_ALLOW"
`
		deleteProfileName = "delete-me"
		deletePod         = `
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
  - name: test-container
    image: quay.io/security-profiles-operator/test-nginx:1.19.1
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
    image: quay.io/security-profiles-operator/test-nginx:1.19.1
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
    image: quay.io/security-profiles-operator/test-nginx:1.19.1
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
    image: quay.io/security-profiles-operator/test-nginx:1.19.1
`
		deletePodName = "test-pod"
	)

	profileCleanup := e.writeAndCreate(deleteProfile, "delete-profile*.yaml")
	defer profileCleanup()

	namespace := e.getCurrentContextNamespace(defaultNamespace)
	sp := e.getSeccompProfile(deleteProfileName, namespace)
	path := sp.GetProfilePath()

	e.logf("Waiting for profile to be reconciled")
	e.waitFor("condition=ready", "seccompprofile", deleteProfileName)

	e.logf("Verifying profile exists")
	time.Sleep(time.Second)
	for _, node := range nodes {
		e.execNode(node, "test", "-f", path)
	}
	e.logf("Verifying profile deleted")
	e.kubectl("delete", "seccompprofile", deleteProfileName)
	time.Sleep(time.Second)
	for _, node := range nodes {
		e.execNode(node, "test", "!", "-f", path)
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
		defer profileCleanup()
		e.waitFor("condition=ready", "seccompprofile", deleteProfileName)
		podCleanup := e.writeAndCreate(fmt.Sprintf(testCase.podManifest, namespace), "delete-pod*.yaml")
		defer podCleanup()
		e.waitFor("condition=ready", "pod", deletePodName)
		e.logf("Ensuring profile cannot be deleted while pod is active")
		e.kubectl("delete", "seccompprofile", deleteProfileName, "--wait=0")

		e.logf("Waiting for profile to be marked as terminating but not deleted")
		// TODO(jhrozek): deleting manifests as Ready=False, reason=Deleting, can we wait in a nicer way?
		for i := 0; i < 10; i++ {
			sp := e.getSeccompProfile(deleteProfileName, namespace)
			conReady := sp.Status.GetCondition(v1.TypeReady)
			if conReady.Reason == v1.ReasonDeleting {
				break
			}
			time.Sleep(time.Second)
		}

		// At this point it must be terminating or else we haven't matched the condition above
		sp := e.getSeccompProfile(deleteProfileName, namespace)
		e.Equal(sp.Status.Status, secprofnodestatusv1alpha1.ProfileStateTerminating)

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
