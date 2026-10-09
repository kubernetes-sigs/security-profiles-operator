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

package workloadannotator

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/events"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const testPodName = "test-pod"

func annotatorScheme(t *testing.T) *runtime.Scheme {
	t.Helper()

	s := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(s))
	require.NoError(t, seccompprofileapi.AddToScheme(s))
	require.NoError(t, selinuxprofileapi.AddToScheme(s))
	require.NoError(t, apparmorprofileapi.AddToScheme(s))

	return s
}

func newAnnotator(
	t *testing.T, funcs *interceptor.Funcs, objs ...client.Object,
) (*PodReconciler, client.Client, *events.FakeRecorder) {
	t.Helper()

	builder := fake.NewClientBuilder().
		WithScheme(annotatorScheme(t)).
		WithObjects(objs...).
		WithStatusSubresource(
			&seccompprofileapi.SeccompProfile{},
			&selinuxprofileapi.SelinuxProfile{},
			&selinuxprofileapi.RawSelinuxProfile{},
			&apparmorprofileapi.AppArmorProfile{},
		).
		WithIndex(&corev1.Pod{}, spOwnerKey, podIndex(getSeccompProfilesFromPod)).
		WithIndex(&corev1.Pod{}, seOwnerKey, podIndex(getSelinuxProfilesFromPod)).
		WithIndex(&corev1.Pod{}, aaOwnerKey, podIndex(getAppArmorProfilesFromPod)).
		WithIndex(&seccompprofileapi.SeccompProfile{}, linkedPodsKey, workloadIndex).
		WithIndex(&selinuxprofileapi.SelinuxProfile{}, linkedPodsKey, workloadIndex).
		WithIndex(&selinuxprofileapi.RawSelinuxProfile{}, linkedPodsKey, workloadIndex).
		WithIndex(&apparmorprofileapi.AppArmorProfile{}, linkedPodsKey, workloadIndex)

	if funcs != nil {
		builder = builder.WithInterceptorFuncs(*funcs)
	}

	c := builder.Build()
	rec := events.NewFakeRecorder(10)

	return &PodReconciler{client: c, reader: c, log: logr.Discard(), record: rec}, c, rec
}

func reconcilePod(t *testing.T, r *PodReconciler) error {
	t.Helper()

	_, err := r.Reconcile(t.Context(), reconcile.Request{
		NamespacedName: client.ObjectKey{Namespace: "default", Name: testPodName},
	})

	return err
}

func podWith(mutate func(*corev1.Pod)) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: testPodName, Namespace: "default"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name:            "ctr",
			Image:           "image",
			SecurityContext: &corev1.SecurityContext{},
		}}},
	}
	mutate(pod)

	return pod
}

func withSeccomp(path string) func(*corev1.Pod) {
	return func(pod *corev1.Pod) {
		pod.Spec.Containers[0].SecurityContext.SeccompProfile = &corev1.SeccompProfile{
			Type:             corev1.SeccompProfileTypeLocalhost,
			LocalhostProfile: &path,
		}
	}
}

func withSelinuxType(selinuxType string) func(*corev1.Pod) {
	return func(pod *corev1.Pod) {
		pod.Spec.Containers[0].SecurityContext.SELinuxOptions = &corev1.SELinuxOptions{
			Type: selinuxType,
		}
	}
}

func withAppArmor(name string) func(*corev1.Pod) {
	return func(pod *corev1.Pod) {
		pod.Spec.Containers[0].SecurityContext.AppArmorProfile = &corev1.AppArmorProfile{
			Type:             corev1.AppArmorProfileTypeLocalhost,
			LocalhostProfile: &name,
		}
	}
}

func objectMeta(name string, finalizers ...string) metav1.ObjectMeta {
	return metav1.ObjectMeta{Name: name, Finalizers: finalizers}
}

func requireInUse(t *testing.T, c client.Client, obj client.Object, want bool) {
	t.Helper()

	require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(obj), obj))
	require.Equal(t, want,
		slices.Contains(obj.GetFinalizers(), util.HasActivePodsFinalizerString),
		"in use finalizer of %s", obj.GetName())
}

func TestReconcileMarksSeccompProfileInUse(t *testing.T) {
	t.Parallel()

	for name, profileName := range map[string]string{
		"name without suffix": "foo",
		"name with suffix":    "foo.json",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			sp := &seccompprofileapi.SeccompProfile{ObjectMeta: objectMeta(profileName)}
			r, c, _ := newAnnotator(t, nil, sp, podWith(withSeccomp("operator/foo.json")))

			require.NoError(t, reconcilePod(t, r))
			requireInUse(t, c, sp, true)
			require.Equal(t, []string{"default/" + testPodName}, sp.Status.ActiveWorkloads)
		})
	}
}

func TestSeccompProfilesForPathRejectsOtherFiles(t *testing.T) {
	t.Parallel()

	// "a.json" is stored as operator/a.json, not as operator/a.json.json.
	r, _, _ := newAnnotator(t, nil,
		&seccompprofileapi.SeccompProfile{ObjectMeta: objectMeta("a.json")})

	profiles, err := r.seccompProfilesForPath(t.Context(), "operator/a.json.json")
	require.NoError(t, err)
	require.Empty(t, profiles)
}

func TestReconcileContinuesPastMissingProfile(t *testing.T) {
	t.Parallel()

	se := &selinuxprofileapi.SelinuxProfile{ObjectMeta: objectMeta("present")}
	pod := podWith(func(pod *corev1.Pod) {
		withSeccomp("operator/missing.json")(pod)
		withSelinuxType("present.process")(pod)
	})
	r, c, rec := newAnnotator(t, nil, se, pod)

	require.NoError(t, reconcilePod(t, r), "a missing profile is picked up once it is created")
	requireInUse(t, c, se, true)
	require.Contains(
		t,
		<-rec.Events,
		"SeccompProfile operator/missing.json used by the pod not found",
	)
}

func TestReconcileMarksRawSelinuxAndAppArmorProfilesInUse(t *testing.T) {
	t.Parallel()

	raw := &selinuxprofileapi.RawSelinuxProfile{ObjectMeta: objectMeta("raw")}
	aa := &apparmorprofileapi.AppArmorProfile{ObjectMeta: objectMeta("aa")}
	pod := podWith(func(pod *corev1.Pod) {
		withSelinuxType("raw.process")(pod)
		withAppArmor("aa")(pod)
	})
	r, c, _ := newAnnotator(t, nil, raw, aa, pod)

	require.NoError(t, reconcilePod(t, r))
	requireInUse(t, c, raw, true)
	requireInUse(t, c, aa, true)
	require.Equal(t, []string{"default/" + testPodName}, raw.Status.ActiveWorkloads)
	require.Equal(t, []string{"default/" + testPodName}, aa.Status.ActiveWorkloads)
	require.EqualValues(t, 1, raw.Status.ActiveWorkloadsCount)
	require.EqualValues(t, 1, aa.Status.ActiveWorkloadsCount)
}

func TestReconcileIgnoresForeignAppArmorProfile(t *testing.T) {
	t.Parallel()

	r, _, rec := newAnnotator(t, nil, podWith(withAppArmor("host-profile")))

	require.NoError(t, reconcilePod(t, r))
	require.Empty(t, rec.Events)
}

func TestReconcileReportsLookupErrors(t *testing.T) {
	t.Parallel()

	errLookup := errors.New("api down")
	se := &selinuxprofileapi.SelinuxProfile{ObjectMeta: objectMeta("present")}
	pod := podWith(func(pod *corev1.Pod) {
		withSeccomp("operator/broken.json")(pod)
		withSelinuxType("present.process")(pod)
	})

	r, c, rec := newAnnotator(t, &interceptor.Funcs{
		Get: func(
			ctx context.Context, cl client.WithWatch, key client.ObjectKey,
			obj client.Object, opts ...client.GetOption,
		) error {
			if _, ok := obj.(*seccompprofileapi.SeccompProfile); ok {
				return errLookup
			}

			return cl.Get(ctx, key, obj, opts...)
		},
	}, se, pod)

	require.ErrorIs(t, reconcilePod(t, r), errLookup)
	requireInUse(t, c, se, true)
	require.Contains(t, <-rec.Events, "api down")
}

func TestReconcilePodDeletionReleasesProfiles(t *testing.T) {
	t.Parallel()

	podID := "default/" + testPodName
	sp := &seccompprofileapi.SeccompProfile{
		ObjectMeta: objectMeta("foo", util.HasActivePodsFinalizerString),
		Status:     seccompprofileapi.SeccompProfileStatus{ActiveWorkloads: []string{podID}},
	}
	se := &selinuxprofileapi.SelinuxProfile{
		ObjectMeta: objectMeta("se", util.HasActivePodsFinalizerString),
		Status:     selinuxprofileapi.SelinuxProfileStatus{ActiveWorkloads: []string{podID}},
	}
	raw := &selinuxprofileapi.RawSelinuxProfile{
		ObjectMeta: objectMeta("raw", util.HasActivePodsFinalizerString),
		Status:     selinuxprofileapi.SelinuxProfileStatus{ActiveWorkloads: []string{podID}},
	}
	aa := &apparmorprofileapi.AppArmorProfile{
		ObjectMeta: objectMeta("aa", util.HasActivePodsFinalizerString),
		Status: apparmorprofileapi.AppArmorProfileStatus{
			ActiveWorkloads: []string{"default/other", podID},
		},
	}

	// Another pod still uses the AppArmor profile.
	other := podWith(withAppArmor("aa"))
	other.Name = "other"

	r, c, _ := newAnnotator(t, nil, sp, se, raw, aa, other)

	require.NoError(t, reconcilePod(t, r))
	requireInUse(t, c, sp, false)
	require.Empty(t, sp.Status.ActiveWorkloads)
	requireInUse(t, c, se, false)
	requireInUse(t, c, raw, false)
	require.Empty(t, raw.Status.ActiveWorkloads)
	requireInUse(t, c, aa, true)
	require.Equal(t, []string{"default/other"}, aa.Status.ActiveWorkloads)
	require.EqualValues(t, 1, aa.Status.ActiveWorkloadsCount)
}

// A completed pod, like the one of a finished Job, keeps its object, but
// releases its profiles.
func TestReconcileCompletedPodReleasesProfiles(t *testing.T) {
	t.Parallel()

	sp := &seccompprofileapi.SeccompProfile{ObjectMeta: objectMeta("foo")}
	pod := podWith(withSeccomp("operator/foo.json"))
	r, c, _ := newAnnotator(t, nil, sp, pod)

	require.NoError(t, reconcilePod(t, r))
	requireInUse(t, c, sp, true)

	pod.Status.Phase = corev1.PodSucceeded
	require.NoError(t, c.Status().Update(t.Context(), pod))

	require.NoError(t, reconcilePod(t, r))
	requireInUse(t, c, sp, false)
	require.Empty(t, sp.Status.ActiveWorkloads)
	require.Zero(t, sp.Status.ActiveWorkloadsCount)
}

func TestProfileWorkloadRequests(t *testing.T) {
	t.Parallel()

	early := podWith(withAppArmor("aa"))
	r, _, _ := newAnnotator(t, nil, early)

	// A profile created after its pod finds the pod through the index.
	requests := r.profileWorkloadRequests(t.Context(), &apparmorprofileapi.AppArmorProfile{
		ObjectMeta: objectMeta("aa"),
	})
	require.Equal(t, []reconcile.Request{{
		NamespacedName: client.ObjectKey{Namespace: "default", Name: testPodName},
	}}, requests)

	// Pods from the status are not duplicated.
	sp := &seccompprofileapi.SeccompProfile{ObjectMeta: objectMeta("foo")}
	sp.Status.ActiveWorkloads = []string{"default/" + testPodName}
	require.Len(t, r.profileWorkloadRequests(t.Context(), sp), 1)

	require.Empty(t, r.profileWorkloadRequests(t.Context(), &corev1.Pod{}))
}

func TestGetAppArmorProfilesFromPod(t *testing.T) {
	t.Parallel()

	name := "ctr-profile"
	pod := podWith(withAppArmor(name))
	pod.Spec.SecurityContext = &corev1.PodSecurityContext{
		AppArmorProfile: &corev1.AppArmorProfile{Type: corev1.AppArmorProfileTypeRuntimeDefault},
	}
	pod.Annotations = map[string]string{
		corev1.DeprecatedAppArmorBetaContainerAnnotationKeyPrefix + "ctr": "localhost/annotated",
		corev1.DeprecatedAppArmorBetaContainerAnnotationKeyPrefix + "rt":  "runtime/default",
		"unrelated": "localhost/ignored",
	}

	require.Equal(t, []string{"annotated", name}, getAppArmorProfilesFromPod(pod))
	require.True(t, hasProfile(pod))
	require.False(t, hasProfile(&corev1.Pod{}))
	require.False(t, hasProfile(&corev1.Node{}))
}

func TestIsOperatorSelinuxType(t *testing.T) {
	t.Parallel()

	require.True(t, isOperatorSelinuxType(&corev1.SELinuxOptions{Type: "profile.process"}))
	require.False(t, isOperatorSelinuxType(&corev1.SELinuxOptions{Type: ".process"}))
	require.False(t, isOperatorSelinuxType(&corev1.SELinuxOptions{Type: "container_t"}))
	require.False(t, isOperatorSelinuxType(nil))
}

func TestReconcileIgnoresForeignSelinuxType(t *testing.T) {
	t.Parallel()

	// A type created by another tool, for example udica.
	r, _, rec := newAnnotator(t, nil, podWith(withSelinuxType("my_container.process")))

	require.NoError(t, reconcilePod(t, r))
	require.Empty(t, rec.Events)
}

// A pod which went away while the operator was down produces no pod event,
// so the profile itself has to release the in-use finalizer.
func TestProfileReconcilerReleasesUnusedProfiles(t *testing.T) {
	t.Parallel()

	// Profiles of a version without active workloads for these kinds.
	unused := &apparmorprofileapi.AppArmorProfile{
		ObjectMeta: objectMeta("unused", util.HasActivePodsFinalizerString),
	}
	used := &apparmorprofileapi.AppArmorProfile{
		ObjectMeta: objectMeta("used", util.HasActivePodsFinalizerString),
	}
	raw := &selinuxprofileapi.RawSelinuxProfile{
		ObjectMeta: objectMeta("raw", util.HasActivePodsFinalizerString),
	}
	sp := &seccompprofileapi.SeccompProfile{
		ObjectMeta: objectMeta("foo", util.HasActivePodsFinalizerString),
		Status: seccompprofileapi.SeccompProfileStatus{
			ActiveWorkloads: []string{"default/gone"}, ActiveWorkloadsCount: 1,
		},
	}
	r, c, _ := newAnnotator(t, nil, unused, used, raw, sp, podWith(withAppArmor("used")))

	appArmor := &profileReconciler[*apparmorprofileapi.AppArmorProfile]{pods: r, kind: appArmorKind}
	rawSelinux := &profileReconciler[*selinuxprofileapi.RawSelinuxProfile]{
		pods: r,
		kind: rawSelinuxKind,
	}
	seccomp := &profileReconciler[*seccompprofileapi.SeccompProfile]{pods: r, kind: seccompKind}

	for _, tc := range []struct {
		reconciler reconcile.Reconciler
		name       string
	}{
		{appArmor, "unused"},
		{appArmor, "used"},
		{appArmor, "gone"},
		{rawSelinux, "raw"},
		{seccomp, "foo"},
	} {
		_, err := tc.reconciler.Reconcile(t.Context(), reconcile.Request{
			NamespacedName: client.ObjectKey{Name: tc.name},
		})
		require.NoError(t, err)
	}

	requireInUse(t, c, unused, false)
	requireInUse(t, c, used, true)
	require.Equal(t, []string{"default/" + testPodName}, used.Status.ActiveWorkloads)
	requireInUse(t, c, raw, false)
	requireInUse(t, c, sp, false)
	require.Empty(t, sp.Status.ActiveWorkloads)
}

// The reconcile of a pod deleted right after the reconcile which listed it
// in a profile can miss the profile, because the cache does not have that
// update yet. Once the cache has it, the profile gets reconciled and released.
func TestProfileReconcilerReleasesPodDeletedBeforeCacheUpdate(t *testing.T) {
	t.Parallel()

	sp := &seccompprofileapi.SeccompProfile{ObjectMeta: objectMeta("foo")}
	pod := podWith(withSeccomp("operator/foo.json"))
	r, c, _ := newAnnotator(t, nil, sp, pod)
	stale := sp.DeepCopy()

	require.NoError(t, reconcilePod(t, r))
	requireInUse(t, c, sp, true)

	// The deletion got reconciled with a cache which missed the update, so
	// no profile listed the pod and nothing got released.
	require.NoError(t, c.Delete(t.Context(), pod))
	requireInUse(t, c, sp, true)

	// The cache gets the update, which reconciles the profile.
	require.True(
		t,
		profileWorkloadsPredicate.Update(event.UpdateEvent{ObjectOld: stale, ObjectNew: sp}),
	)

	_, err := (&profileReconciler[*seccompprofileapi.SeccompProfile]{pods: r, kind: seccompKind}).
		Reconcile(t.Context(), reconcile.Request{NamespacedName: client.ObjectKeyFromObject(sp)})
	require.NoError(t, err)
	requireInUse(t, c, sp, false)
	require.Empty(t, sp.Status.ActiveWorkloads)
}

// A pod deletion only checks the profiles which list the pod, not every
// profile in the cluster.
func TestReconcilePodDeletionOnlyChecksListingProfiles(t *testing.T) {
	t.Parallel()

	listing := &apparmorprofileapi.AppArmorProfile{
		ObjectMeta: objectMeta("listing", util.HasActivePodsFinalizerString),
		Status: apparmorprofileapi.AppArmorProfileStatus{
			ActiveWorkloads: []string{"default/" + testPodName}, ActiveWorkloadsCount: 1,
		},
	}
	// Lists a pod which is gone as well, but not the reconciled one.
	other := &apparmorprofileapi.AppArmorProfile{
		ObjectMeta: objectMeta("other", util.HasActivePodsFinalizerString),
		Status: apparmorprofileapi.AppArmorProfileStatus{
			ActiveWorkloads: []string{"default/gone"}, ActiveWorkloadsCount: 1,
		},
	}

	r, c, _ := newAnnotator(t, nil, listing, other)

	require.NoError(t, reconcilePod(t, r))
	requireInUse(t, c, listing, false)
	requireInUse(t, c, other, true)
}

func TestWorkloadIndex(t *testing.T) {
	t.Parallel()

	aa := &apparmorprofileapi.AppArmorProfile{}
	aa.Status.ActiveWorkloads = []string{"ns/a", "ns/b"}
	aa.Status.ActiveWorkloadsCount = 2
	require.Equal(t, []string{"ns/a", "ns/b"}, workloadIndex(aa))

	// A profile which lists only part of its pods may count any pod.
	aa.Status.ActiveWorkloadsCount = 3
	require.Equal(t, []string{"ns/a", "ns/b", truncatedValue}, workloadIndex(aa))
	require.Equal(t, []string{"ns/a", "ns/b"}, aa.Status.ActiveWorkloads)

	require.Empty(t, workloadIndex(&selinuxprofileapi.RawSelinuxProfile{}))
	require.Empty(t, workloadIndex(&corev1.Pod{}))
}

// A pod recorded with the log recorder runs every container, including init
// containers, with the log enricher profile. Once the pod is gone, the
// profile must not be kept in use, otherwise it can never be deleted.
func TestReconcileReleasesLogEnricherProfileAfterRecording(t *testing.T) {
	t.Parallel()

	const profileName = "log-enricher-trace"

	profile := &seccompprofileapi.SeccompProfile{
		ObjectMeta: objectMeta(profileName, util.GetFinalizerNodeString("node")),
	}
	pod := podWith(withSeccomp("operator/" + profileName + ".json"))
	pod.Spec.InitContainers = []corev1.Container{{
		Name:            "init",
		SecurityContext: pod.Spec.Containers[0].SecurityContext.DeepCopy(),
	}}
	pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{
		Name:            "redis",
		SecurityContext: pod.Spec.Containers[0].SecurityContext.DeepCopy(),
	})

	r, c, _ := newAnnotator(t, nil, profile, pod)

	require.NoError(t, reconcilePod(t, r))
	requireInUse(t, c, profile, true)

	require.NoError(t, c.Delete(t.Context(), pod))
	require.NoError(t, reconcilePod(t, r))
	requireInUse(t, c, profile, false)
	require.Empty(t, profile.Status.ActiveWorkloads)
	require.Equal(t, []string{util.GetFinalizerNodeString("node")}, profile.GetFinalizers())
}

// A failure with one profile kind must not keep the profiles of the other
// kinds in use.
func TestReconcilePodDeletionReleasesDespiteOtherKindFailing(t *testing.T) {
	t.Parallel()

	podID := "default/" + testPodName
	profile := &seccompprofileapi.SeccompProfile{
		ObjectMeta: objectMeta("foo", util.HasActivePodsFinalizerString),
		Status:     seccompprofileapi.SeccompProfileStatus{ActiveWorkloads: []string{podID}},
	}

	errList := errors.New("cannot list")

	r, c, _ := newAnnotator(t, &interceptor.Funcs{
		List: func(
			ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption,
		) error {
			if _, ok := list.(*apparmorprofileapi.AppArmorProfileList); ok {
				return errList
			}

			return cl.List(ctx, list, opts...)
		},
	}, profile)

	require.ErrorIs(t, reconcilePod(t, r), errList)
	requireInUse(t, c, profile, false)
}

// A pod which got replaced by one with the same name, before the deletion of
// the old one got reconciled, must not keep the profiles of the old one in
// use.
func TestReconcileSameNamePodReleasesUnusedProfiles(t *testing.T) {
	t.Parallel()

	podID := "default/" + testPodName
	oldSeccomp := &seccompprofileapi.SeccompProfile{
		ObjectMeta: objectMeta("old", util.HasActivePodsFinalizerString),
		Status:     seccompprofileapi.SeccompProfileStatus{ActiveWorkloads: []string{podID}},
	}
	newSeccomp := &seccompprofileapi.SeccompProfile{ObjectMeta: objectMeta("new")}
	oldSelinux := &selinuxprofileapi.SelinuxProfile{
		ObjectMeta: objectMeta("old-se", util.HasActivePodsFinalizerString),
		Status:     selinuxprofileapi.SelinuxProfileStatus{ActiveWorkloads: []string{podID}},
	}

	r, c, _ := newAnnotator(t, nil, oldSeccomp, newSeccomp, oldSelinux,
		podWith(withSeccomp("operator/new.json")))

	require.NoError(t, reconcilePod(t, r))
	requireInUse(t, c, oldSeccomp, false)
	require.Empty(t, oldSeccomp.Status.ActiveWorkloads)
	requireInUse(t, c, oldSelinux, false)
	require.Empty(t, oldSelinux.Status.ActiveWorkloads)
	requireInUse(t, c, newSeccomp, true)
	require.Equal(t, []string{podID}, newSeccomp.Status.ActiveWorkloads)
}

// The AppArmor and raw SELinux profiles of a pod which got replaced by one
// with the same name are released as well.
func TestReconcileSameNamePodReleasesAppArmorAndRawSelinuxProfiles(t *testing.T) {
	t.Parallel()

	raw := &selinuxprofileapi.RawSelinuxProfile{ObjectMeta: objectMeta("raw")}
	aa := &apparmorprofileapi.AppArmorProfile{ObjectMeta: objectMeta("aa")}
	oldPod := podWith(func(pod *corev1.Pod) {
		pod.UID = "old"
		withSelinuxType("raw.process")(pod)
		withAppArmor("aa")(pod)
	})
	r, c, _ := newAnnotator(t, nil, raw, aa, oldPod)

	require.NoError(t, reconcilePod(t, r))
	requireInUse(t, c, raw, true)
	requireInUse(t, c, aa, true)

	require.NoError(t, c.Delete(t.Context(), oldPod))
	require.NoError(t, c.Create(t.Context(), podWith(func(pod *corev1.Pod) {
		pod.UID = "new"
	})))

	require.NoError(t, reconcilePod(t, r))
	requireInUse(t, c, raw, false)
	requireInUse(t, c, aa, false)
}

// A pod event for profiles which the cache shows with the current pods and
// the finalizer needs no read from the API server and no write.
func TestUpdatePodReferencesUsesCache(t *testing.T) {
	t.Parallel()

	podID := "default/" + testPodName
	workloads := []string{podID}
	sp := &seccompprofileapi.SeccompProfile{
		ObjectMeta: objectMeta("sp", util.HasActivePodsFinalizerString),
		Status: seccompprofileapi.SeccompProfileStatus{
			ActiveWorkloads: workloads, ActiveWorkloadsCount: 1,
		},
	}
	se := &selinuxprofileapi.SelinuxProfile{
		ObjectMeta: objectMeta("se", util.HasActivePodsFinalizerString),
		Status: selinuxprofileapi.SelinuxProfileStatus{
			ActiveWorkloads: workloads, ActiveWorkloadsCount: 1,
		},
	}
	raw := &selinuxprofileapi.RawSelinuxProfile{
		ObjectMeta: objectMeta("se", util.HasActivePodsFinalizerString),
		Status: selinuxprofileapi.SelinuxProfileStatus{
			ActiveWorkloads: workloads, ActiveWorkloadsCount: 1,
		},
	}
	aa := &apparmorprofileapi.AppArmorProfile{
		ObjectMeta: objectMeta("aa", util.HasActivePodsFinalizerString),
		Status: apparmorprofileapi.AppArmorProfileStatus{
			ActiveWorkloads: workloads, ActiveWorkloadsCount: 1,
		},
	}
	pod := podWith(func(pod *corev1.Pod) {
		withSeccomp("operator/sp.json")(pod)
		withSelinuxType("se.process")(pod)
		withAppArmor("aa")(pod)
	})

	writes := 0
	r, c, _ := newAnnotator(t, &interceptor.Funcs{
		Update: func(
			ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.UpdateOption,
		) error {
			writes++

			return cl.Update(ctx, obj, opts...)
		},
		SubResourcePatch: func(
			ctx context.Context, cl client.Client, sub string, obj client.Object,
			patch client.Patch, opts ...client.SubResourcePatchOption,
		) error {
			writes++

			return cl.SubResource(sub).Patch(ctx, obj, patch, opts...)
		},
	}, sp, se, raw, aa, pod)
	r.reader = failingReader{}

	require.NoError(t, reconcilePod(t, r))
	requireInUse(t, c, sp, true)
	requireInUse(t, c, se, true)
	requireInUse(t, c, raw, true)
	requireInUse(t, c, aa, true)
	require.Zero(t, writes)
}

// A profile used by more pods than its status lists keeps the in-use
// finalizer and counts all pods, also once a pod which it does not list goes
// away.
func TestReconcileTruncatesActiveWorkloads(t *testing.T) {
	t.Parallel()

	const pods = maxActiveWorkloads + 2

	sp := &seccompprofileapi.SeccompProfile{ObjectMeta: objectMeta("foo")}
	objs := make([]client.Object, 0, 1+pods)
	objs = append(objs, sp)

	for i := range pods {
		pod := podWith(withSeccomp("operator/foo.json"))
		pod.Name = fmt.Sprintf("pod-%04d", i)
		objs = append(objs, pod)
	}

	statusUpdates := 0
	r, c, _ := newAnnotator(t, &interceptor.Funcs{
		SubResourceUpdate: func(
			ctx context.Context, cl client.Client, sub string, obj client.Object,
			opts ...client.SubResourceUpdateOption,
		) error {
			statusUpdates++

			return cl.SubResource(sub).Update(ctx, obj, opts...)
		},
	}, objs...)

	_, err := r.Reconcile(t.Context(), reconcile.Request{
		NamespacedName: client.ObjectKey{Namespace: "default", Name: "pod-0000"},
	})
	require.NoError(t, err)
	requireInUse(t, c, sp, true)
	require.Len(t, sp.Status.ActiveWorkloads, maxActiveWorkloads)
	require.True(t, slices.IsSorted(sp.Status.ActiveWorkloads))
	require.Equal(t, "default/pod-0000", sp.Status.ActiveWorkloads[0])
	require.EqualValues(t, pods, sp.Status.ActiveWorkloadsCount)

	// The last pod is not listed.
	last, ok := objs[pods].(*corev1.Pod)
	require.True(t, ok)
	require.NotContains(t, sp.Status.ActiveWorkloads, "default/"+last.Name)
	require.NoError(t, c.Delete(t.Context(), last))

	_, err = r.Reconcile(
		t.Context(),
		reconcile.Request{NamespacedName: client.ObjectKeyFromObject(last)},
	)
	require.NoError(t, err)
	requireInUse(t, c, sp, true)
	require.Len(t, sp.Status.ActiveWorkloads, maxActiveWorkloads)
	require.EqualValues(t, pods-1, sp.Status.ActiveWorkloadsCount)

	// The status gets patched, not replaced.
	require.Zero(t, statusUpdates)
}

// truncatedAppArmorProfile returns an AppArmor profile in use which lists
// only part of its pods.
func truncatedAppArmorProfile(name string) *apparmorprofileapi.AppArmorProfile {
	return &apparmorprofileapi.AppArmorProfile{
		ObjectMeta: objectMeta(name, util.HasActivePodsFinalizerString),
		Status: apparmorprofileapi.AppArmorProfileStatus{
			ActiveWorkloads: []string{"default/listed"}, ActiveWorkloadsCount: 5,
		},
	}
}

// A pod deletion used to update every profile which lists only part of its
// pods, which lists and sorts all their pods. Only the ones the deleted pod
// used get updated now, unless the pod is unknown.
func TestReconcilePodDeletionOnlyChecksTruncatedProfilesOfPod(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		deleteEvent bool
		wantOther   int32
	}{
		"pod known from its delete event": {deleteEvent: true, wantOther: 5},
		"unknown pod":                     {wantOther: 0},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			used := truncatedAppArmorProfile("used")
			other := truncatedAppArmorProfile("other")
			pod := podWith(withAppArmor("used"))
			listedPod := podWith(withAppArmor("used"))
			listedPod.Name = "listed"

			r, c, _ := newAnnotator(t, nil, used, other, pod, listedPod)

			require.NoError(t, c.Delete(t.Context(), pod))

			if tc.deleteEvent {
				h := &podEventHandler{EventHandler: &handler.EnqueueRequestForObject{}, pods: r}
				q := workqueue.NewTypedRateLimitingQueue(
					workqueue.DefaultTypedControllerRateLimiter[reconcile.Request](),
				)
				t.Cleanup(q.ShutDown)

				h.Delete(t.Context(), event.DeleteEvent{Object: pod}, q)
				require.Equal(t, 1, q.Len())

				_, known := r.deletedPod("default/" + testPodName)
				require.True(t, known)
			}

			require.NoError(t, reconcilePod(t, r))

			// The profile of the pod gets its count updated.
			requireInUse(t, c, used, true)
			require.Equal(t, []string{"default/listed"}, used.Status.ActiveWorkloads)
			require.EqualValues(t, 1, used.Status.ActiveWorkloadsCount)

			// The other profile only gets updated if the pod is unknown.
			require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(other), other))
			require.Equal(t, tc.wantOther, other.Status.ActiveWorkloadsCount)

			// The references of the pod are dropped once the deletion got
			// reconciled.
			_, known := r.deletedPod("default/" + testPodName)
			require.False(t, known)
		})
	}
}

// A pod replaced by one with the same name before the deletion of the old
// one got reconciled releases the profiles which list only part of their
// pods and which only the old pod used.
func TestReconcileSameNamePodReleasesTruncatedProfiles(t *testing.T) {
	t.Parallel()

	old := truncatedAppArmorProfile("old")
	current := &apparmorprofileapi.AppArmorProfile{ObjectMeta: objectMeta("current")}
	pod := podWith(withAppArmor("current"))

	r, c, _ := newAnnotator(t, nil, old, current, pod)
	r.rememberDeletedPod(podWith(withAppArmor("old")))

	require.NoError(t, reconcilePod(t, r))
	requireInUse(t, c, old, false)
	require.Zero(t, old.Status.ActiveWorkloadsCount)
	requireInUse(t, c, current, true)

	_, known := r.deletedPod("default/" + testPodName)
	require.False(t, known)
}

func TestActiveWorkloads(t *testing.T) {
	t.Parallel()

	pods := make([]string, 0, maxActiveWorkloads+2)
	for i := range maxActiveWorkloads + 2 {
		pods = append(pods, fmt.Sprintf("ns/pod-%04d", i))
	}

	first := slices.Clone(pods[:maxActiveWorkloads])
	shuffled := slices.Clone(pods)
	slices.Reverse(shuffled)

	for name, tc := range map[string]struct {
		pods, current []string
		want          []string
	}{
		"no pods": {current: []string{"ns/gone"}},
		"unsorted pods": {
			pods: []string{"ns/b", "ns/a"}, want: []string{"ns/a", "ns/b"},
		},
		"listed pods unchanged": {
			pods: []string{"ns/b", "ns/a"}, current: []string{"ns/a", "ns/b"},
			want: []string{"ns/a", "ns/b"},
		},
		"listed pod gone": {
			pods: []string{"ns/c", "ns/a"}, current: []string{"ns/a", "ns/b"},
			want: []string{"ns/a", "ns/c"},
		},
		"truncated, unlisted pod gone": {
			pods: shuffled[1:], current: first, want: first,
		},
		"truncated, listed pod gone": {
			pods: shuffled[:len(shuffled)-1], current: first, want: pods[1 : maxActiveWorkloads+1],
		},
		"truncated, pod added in front": {
			pods: append(slices.Clone(shuffled[1:]), "ns/a"), current: first,
			want: append([]string{"ns/a"}, first[:maxActiveWorkloads-1]...),
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			listed, total := activeWorkloads(tc.pods, tc.current)
			require.Equal(t, tc.want, listed)
			require.EqualValues(t, len(tc.pods), total)
		})
	}
}

// The API server rejects adding a finalizer to a profile which is being
// deleted, so the profile only lists the pod.
func TestReconcileDoesNotAddFinalizerToDeletingProfile(t *testing.T) {
	t.Parallel()

	now := metav1.Now()
	sp := &seccompprofileapi.SeccompProfile{
		ObjectMeta: objectMeta("foo", util.GetFinalizerNodeString("node")),
	}
	sp.DeletionTimestamp = &now

	updates := 0
	r, c, _ := newAnnotator(t, &interceptor.Funcs{
		Update: func(
			ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.UpdateOption,
		) error {
			updates++

			return cl.Update(ctx, obj, opts...)
		},
	}, sp, podWith(withSeccomp("operator/foo.json")))

	require.NoError(t, reconcilePod(t, r))
	requireInUse(t, c, sp, false)
	require.Equal(t, []string{"default/" + testPodName}, sp.Status.ActiveWorkloads)
	require.Zero(t, updates)
}

// A patch based on a cache which is behind fails with a conflict, and the
// retry reads the profile from the API server.
func TestUpdatePodReferencesRetriesStaleCache(t *testing.T) {
	t.Parallel()

	sp := &seccompprofileapi.SeccompProfile{ObjectMeta: objectMeta("foo")}
	conflicts := 0
	r, c, _ := newAnnotator(t, &interceptor.Funcs{
		SubResourcePatch: func(
			ctx context.Context, cl client.Client, sub string, obj client.Object,
			patch client.Patch, opts ...client.SubResourcePatchOption,
		) error {
			err := cl.SubResource(sub).Patch(ctx, obj, patch, opts...)
			if kerrors.IsConflict(err) {
				conflicts++
			}

			return err
		},
	}, sp, podWith(withSeccomp("operator/foo.json")))

	stale := &seccompprofileapi.SeccompProfile{}
	require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(sp), stale))

	// Another writer changes the profile after the cache got it.
	current := stale.DeepCopy()
	current.Status.ActiveWorkloads = []string{"default/other"}
	require.NoError(t, c.Status().Update(t.Context(), current))

	require.NoError(t, r.updatePodReferencesForSeccomp(t.Context(), stale))
	require.Equal(t, 1, conflicts)
	requireInUse(t, c, sp, true)
	require.Equal(t, []string{"default/" + testPodName}, sp.Status.ActiveWorkloads)
}

// failingReader is a client.Reader which fails every read.
type failingReader struct{}

func (failingReader) Get(
	context.Context,
	client.ObjectKey,
	client.Object,
	...client.GetOption,
) error {
	return errors.New("unexpected read from the API server")
}

func (failingReader) List(context.Context, client.ObjectList, ...client.ListOption) error {
	return errors.New("unexpected read from the API server")
}

// conflictOnce returns an error for the first write, after creating the pod
// like a concurrent reconcile of a new pod using the same profile would.
func conflictOnce(t *testing.T, pod *corev1.Pod) func(context.Context, client.Client) error {
	t.Helper()

	conflicted := false

	return func(ctx context.Context, cl client.Client) error {
		if conflicted {
			return nil
		}

		conflicted = true

		require.NoError(t, cl.Create(ctx, pod))

		return kerrors.NewConflict(
			schema.GroupResource{},
			"profile",
			errors.New("concurrent update"),
		)
	}
}

// A pod which starts using the profile while the deletion of another pod
// gets reconciled stays tracked, and the profile stays in use.
func TestReconcilePodDeletionRecomputesActiveWorkloadsOnConflict(t *testing.T) {
	t.Parallel()

	sp := &seccompprofileapi.SeccompProfile{
		ObjectMeta: objectMeta("foo", util.HasActivePodsFinalizerString),
		Status: seccompprofileapi.SeccompProfileStatus{
			ActiveWorkloads: []string{"default/" + testPodName},
		},
	}

	other := podWith(withSeccomp("operator/foo.json"))
	other.Name = "other"
	conflict := conflictOnce(t, other)

	r, c, _ := newAnnotator(t, &interceptor.Funcs{
		SubResourcePatch: func(
			ctx context.Context, cl client.Client, sub string, obj client.Object,
			patch client.Patch, opts ...client.SubResourcePatchOption,
		) error {
			if err := conflict(ctx, cl); err != nil {
				return err
			}

			return cl.SubResource(sub).Patch(ctx, obj, patch, opts...)
		},
	}, sp)

	require.NoError(t, reconcilePod(t, r))
	requireInUse(t, c, sp, true)
	require.Equal(t, []string{"default/other"}, sp.Status.ActiveWorkloads)
}

// The finalizer of a profile is only removed if no pod uses the profile once
// the removal gets written.
func TestReconcilePodDeletionKeepsFinalizerOnConflict(t *testing.T) {
	t.Parallel()

	aa := &apparmorprofileapi.AppArmorProfile{
		ObjectMeta: objectMeta("aa", util.HasActivePodsFinalizerString),
		Status: apparmorprofileapi.AppArmorProfileStatus{
			ActiveWorkloads: []string{"default/" + testPodName}, ActiveWorkloadsCount: 1,
		},
	}

	other := podWith(withAppArmor("aa"))
	other.Name = "other"
	conflict := conflictOnce(t, other)

	r, c, _ := newAnnotator(t, &interceptor.Funcs{
		Update: func(
			ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.UpdateOption,
		) error {
			if err := conflict(ctx, cl); err != nil {
				return err
			}

			return cl.Update(ctx, obj, opts...)
		},
	}, aa)

	require.NoError(t, reconcilePod(t, r))
	requireInUse(t, c, aa, true)
}
