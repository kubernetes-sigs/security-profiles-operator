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

package e2e_test

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	profilebaseapi "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
)

const (
	containerNameNginx        = "nginx"
	containerNameRedis        = "redis"
	mergeProfileRecordingName = "test-profile-merging"
	profileRecordingTemplate  = `
    apiVersion: security-profiles-operator.x-k8s.io/v1
    kind: ProfileRecording
    metadata:
      name: %s
    spec:
      disableProfileAfterRecording: %s
      kind: %s
      recorder: %s
      mergeStrategy: %s
      podSelector:
        matchLabels:
          %s: %s
`
)

const (
	policyEnabledAfterRecording = iota
	policyDisabledAfterRecording
)

type policyDisableSwitch int

func (e *e2e) testSeccompBpfProfileMerging() {
	e.bpfRecorderOnlyTestCase()

	restoreNs := e.switchToRecordingNs(nsRecordingEnabled)
	defer restoreNs()

	e.profileMergingTest(
		"Bpf",
		"SeccompProfile",
		"sp",
		"/bin/mknod /tmp/foo p",
		"listen",
		"mknod\n", // for some reason bpf recording always allows mknodat(), let's explicitly check mknod()
		policyEnabledAfterRecording,
	)
}

func (e *e2e) testSeccompLogsProfileMerging() {
	e.logEnricherOnlyTestCase()

	restoreNs := e.switchToRecordingNs(nsRecordingEnabled)
	defer restoreNs()

	// Logging every syscall of the starting containers floods the audit
	// subsystem, which then loses whole batches of records before auditd
	// writes them. A syscall like listen, which each container does only once
	// on startup, can be among them, so the common action is epoll_wait, which
	// redis calls ten times a second and nginx on each readiness probe.
	e.profileMergingTest(
		"Logs",
		"SeccompProfile", "sp",
		"/bin/mknod /tmp/foo p",
		"epoll_wait", "mknod",
		policyEnabledAfterRecording,
		"container", "nginx", "syscallName", "epoll_wait")
}

// selinuxMergingTrigger connects to nginx from a process which stays alive for
// a while. The log enricher looks up the container of an audit line through
// its process, so the denial of a short lived curl can get lost.
const selinuxMergingTrigger = "exec 3<>/dev/tcp/localhost/8080 && sleep 5"

func (e *e2e) testSelinuxLogsProfileMerging() {
	e.logEnricherOnlyTestCase()
	e.selinuxOnlyTestCase()

	restoreNs := e.switchToRecordingNs(nsRecordingEnabled)
	defer restoreNs()

	e.profileMergingTest(
		"Logs",
		"SelinuxProfile", "selinuxprofile",
		selinuxMergingTrigger,
		"name_bind", "name_connect",
		policyEnabledAfterRecording,
		"perm", "listen",
	)
}

func (e *e2e) testSelinuxLogsDisabledProfileMerging() {
	e.logEnricherOnlyTestCase()
	e.selinuxOnlyTestCase()

	restoreNs := e.switchToRecordingNs(nsRecordingEnabled)
	defer restoreNs()

	e.profileMergingTest(
		"Logs",
		"SelinuxProfile", "selinuxprofile",
		selinuxMergingTrigger,
		"name_bind", "name_connect",
		policyDisabledAfterRecording,
		"perm", "listen",
	)
}

func (e *e2e) profileMergingTest(
	recordedMethod, recorderKind, resource, trigger, commonAction, triggeredAction string,
	isPolicyDisabled policyDisableSwitch,
	logLine ...string,
) {
	const testDeploymentMultiContainer = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-deployment
spec:
  selector:
    matchLabels:
      app: alpine
  replicas: 2
  template:
    metadata:
      labels:
        app: alpine
    spec:
      serviceAccountName: recording-sa
      containers:
      - name: redis
        image: quay.io/security-profiles-operator/redis:6.2.1
        ports:
        - containerPort: 6379
        readinessProbe:
          tcpSocket:
              port: 6379
          initialDelaySeconds: 5
          periodSeconds: 5
      - name: nginx
        image: quay.io/security-profiles-operator/test-nginx-unprivileged:1.21
        ports:
        - containerPort: 8080
        readinessProbe:
          tcpSocket:
              port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
`

	e.logf("Creating a profile recording with merge strategy 'containers'")

	createTemplatedProfileRecording(e, &profileRecTmplMetadata{
		name:           mergeProfileRecordingName,
		recorderKind:   recorderKind,
		recorder:       recordedMethod,
		mergeStrategy:  "Containers",
		labelKey:       "app",
		labelValue:     "alpine",
		policyDisabled: isPolicyDisabled,
	})

	since, deployName := e.createRecordingTestDeploymentFromManifest(testDeploymentMultiContainer)
	podNames := e.getRecordingPodNames()
	suffixes := podSuffixes(podNames)

	switch recordedMethod {
	case "Logs":
		e.waitForEnricherLogsOfPods(since, podNames, logLine...)

	case "Bpf":
		e.waitForBpfRecorderPodLogs(
			since, mergeProfileRecordingName, containerNameNginx, podNames...,
		)

	default:
		e.Failf("unknown recorded method %s", recordedMethod)
	}

	podNamesString := e.kubectl(
		"get",
		"pods",
		"-l",
		"app=alpine",
		"-o",
		"jsonpath={.items[*].metadata.name}",
	)
	onePodName := strings.Fields(podNamesString)[0]
	triggered := time.Now()

	e.kubectl(
		"exec", "-c", containerNameNginx, onePodName, "--", "bash", "-c", trigger,
	)

	if recordedMethod == "Logs" {
		// The recorder collects the profiles from the enricher once the pods
		// are gone, and the enricher runs seconds behind the audit log while
		// the recorded containers are busy. Like the checks of the profiles
		// below, the action only has to be part of the logged value.
		triggeredKey := "syscallName"
		if recorderKind == "SelinuxProfile" {
			triggeredKey = "perm"
		}

		e.waitForEnricherLogs(triggered, regexp.MustCompile(
			`(?m) pod="`+regexp.QuoteMeta(onePodName)+`".* container="`+containerNameNginx+
				`".* `+triggeredKey+`="[^"]*`+regexp.QuoteMeta(triggeredAction)+`[^"]*"`,
		))
	}

	e.kubectl("delete", "deploy", deployName)

	// check that the policies are partial
	for _, sfx := range suffixes {
		for _, containerName := range []string{containerNameNginx, containerNameRedis} {
			recordedProfileName := mergeProfileRecordingName + "-" + containerName + "-" + sfx
			e.logf("Checking that the recorded profile %s is partial", recordedProfileName)

			profile := e.retryGetProfile(resource, recordedProfileName)
			e.Contains(profile, profilebaseapi.ProfilePartialLabel)
			e.Contains(profile, commonAction)

			retryAssertPrfStatus(e, resource, recordedProfileName, "Pending", isPolicyDisabled)

			if containerName == containerNameNginx {
				if strings.HasSuffix(onePodName, sfx) {
					// check the policy from the first container, it should contain the triggered action
					e.Contains(profile, triggeredAction)
				} else {
					// the others should not
					e.NotContains(profile, triggeredAction)
				}
			}
		}
	}

	// delete the recording, this triggers the merge
	e.kubectl("delete", "profilerecording", mergeProfileRecordingName)

	// the partial policies should be gone, instead one policy should be created for each container.
	// Retry a couple of times because removing the partial policies is not atomic. In prod you'd probably list the
	// profiles and check the absence of the partial label.
	mergedProfileNginx := fmt.Sprintf("%s-%s", mergeProfileRecordingName, containerNameNginx)
	mergedProfileRedis := fmt.Sprintf("%s-%s", mergeProfileRecordingName, containerNameRedis)

	e.eventually(2*time.Minute, 5*time.Second, func() error {
		policiesRecorded := strings.Fields(e.kubectl("get", resource,
			"-l", "spo.x-k8s.io/recording-id="+mergeProfileRecordingName,
			"-o", "jsonpath={.items[*].metadata.name}"))

		if len(policiesRecorded) != 2 ||
			!slices.Contains(policiesRecorded, mergedProfileNginx) ||
			!slices.Contains(policiesRecorded, mergedProfileRedis) {
			return fmt.Errorf(
				"want only the merged %s %s and %s, got %v",
				resource, mergedProfileNginx, mergedProfileRedis, policiesRecorded,
			)
		}

		return nil
	})

	// if the recording is supposed to produce disabled policies, check that the merged policy is disabled
	// otherwise the policy should be installed
	retryAssertPrfStatus(e, resource, mergedProfileNginx, "Installed", isPolicyDisabled)

	// the result for the nginx container should contain the triggered action
	mergedProfile := e.retryGetProfile(resource, mergedProfileNginx)
	e.Contains(mergedProfile, triggeredAction)
	e.Contains(mergedProfile, commonAction)
	e.kubectl("delete", resource, mergedProfileNginx, mergedProfileRedis)
}

func retryAssertPrfStatus(
	e *e2e,
	kind, name, enabledState string,
	isPolicyEnabled policyDisableSwitch,
) {
	var expected []string

	switch {
	case isPolicyEnabled == policyDisabledAfterRecording:
		expected = []string{"Disabled"}
	case enabledState == "Installed":
		// let's not bother waiting for the profile to be installed, just the fact that it's
		// being processed is enough
		expected = []string{"Installed", "Pending", "InProgress"}
	default:
		expected = []string{"Partial"}
	}

	// The nodestatus controller may not have picked up the profile yet, and
	// a recorded SELinux profile is Pending until its partial status is set.
	e.eventually(50*time.Second, 5*time.Second, func() error {
		profileStatus := e.kubectl(
			"get", kind, name, "-o", "jsonpath={.status.status}")
		e.logf("The profile %s/%s has a status %q", kind, name, profileStatus)

		if !slices.Contains(expected, profileStatus) {
			return fmt.Errorf("the profile %s/%s has status %q, want one of %v",
				kind, name, profileStatus, expected)
		}

		return nil
	})
}

type profileRecTmplMetadata struct {
	name, recorderKind, recorder, mergeStrategy, labelKey, labelValue string
	policyDisabled                                                    policyDisableSwitch
}

func createTemplatedProfileRecording(e *e2e, metadata *profileRecTmplMetadata) {
	policyDisabledStr := "false"
	if metadata.policyDisabled == policyDisabledAfterRecording {
		policyDisabledStr = "true"
	}

	manifest := fmt.Sprintf(profileRecordingTemplate,
		metadata.name,
		policyDisabledStr,
		metadata.recorderKind, metadata.recorder,
		metadata.mergeStrategy, metadata.labelKey, metadata.labelValue)
	e.writeAndCreate(manifest, metadata.name+".yml")
}
