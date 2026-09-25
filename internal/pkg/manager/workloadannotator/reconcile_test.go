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
	"slices"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
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
		WithIndex(&apparmorprofileapi.AppArmorProfile{}, inUseKey, inUseIndex).
		WithIndex(&selinuxprofileapi.RawSelinuxProfile{}, inUseKey, inUseIndex).
		WithIndex(&seccompprofileapi.SeccompProfile{}, linkedPodsKey, func(o client.Object) []string {
			sp, ok := o.(*seccompprofileapi.SeccompProfile)
			if !ok {
				return nil
			}

			return sp.Status.ActiveWorkloads
		}).
		WithIndex(&selinuxprofileapi.SelinuxProfile{}, linkedPodsKey, func(o client.Object) []string {
			sp, ok := o.(*selinuxprofileapi.SelinuxProfile)
			if !ok {
				return nil
			}

			return sp.Status.ActiveWorkloads
		})

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
	}
	aa := &apparmorprofileapi.AppArmorProfile{
		ObjectMeta: objectMeta("aa", util.HasActivePodsFinalizerString),
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
	requireInUse(t, c, aa, true)
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
func TestProfileReleaserReleasesUnusedProfiles(t *testing.T) {
	t.Parallel()

	unused := &apparmorprofileapi.AppArmorProfile{
		ObjectMeta: objectMeta("unused", util.HasActivePodsFinalizerString),
	}
	used := &apparmorprofileapi.AppArmorProfile{
		ObjectMeta: objectMeta("used", util.HasActivePodsFinalizerString),
	}
	raw := &selinuxprofileapi.RawSelinuxProfile{
		ObjectMeta: objectMeta("raw", util.HasActivePodsFinalizerString),
	}
	r, c, _ := newAnnotator(t, nil, unused, used, raw, podWith(withAppArmor("used")))

	appArmor := &profileReleaser[*apparmorprofileapi.AppArmorProfile]{
		pods:   r,
		newObj: func() *apparmorprofileapi.AppArmorProfile { return &apparmorprofileapi.AppArmorProfile{} },
		release: func(ctx context.Context, r *PodReconciler, p *apparmorprofileapi.AppArmorProfile) error {
			return r.updatePodReferencesForAppArmor(ctx, p)
		},
	}
	rawSelinux := &profileReleaser[*selinuxprofileapi.RawSelinuxProfile]{
		pods:   r,
		newObj: func() *selinuxprofileapi.RawSelinuxProfile { return &selinuxprofileapi.RawSelinuxProfile{} },
		release: func(ctx context.Context, r *PodReconciler, p *selinuxprofileapi.RawSelinuxProfile) error {
			return r.updatePodReferencesForRawSelinux(ctx, p)
		},
	}

	for _, tc := range []struct {
		reconciler reconcile.Reconciler
		name       string
	}{
		{appArmor, "unused"},
		{appArmor, "used"},
		{appArmor, "gone"},
		{rawSelinux, "raw"},
	} {
		_, err := tc.reconciler.Reconcile(t.Context(), reconcile.Request{
			NamespacedName: client.ObjectKey{Name: tc.name},
		})
		require.NoError(t, err)
	}

	requireInUse(t, c, unused, false)
	requireInUse(t, c, used, true)
	requireInUse(t, c, raw, false)
}

// A pod deletion only checks the AppArmor and raw SELinux profiles in use,
// not every profile in the cluster.
func TestReconcilePodDeletionOnlyChecksProfilesInUse(t *testing.T) {
	t.Parallel()

	inUse := &apparmorprofileapi.AppArmorProfile{
		ObjectMeta: objectMeta("in-use", util.HasActivePodsFinalizerString),
	}
	unused := &apparmorprofileapi.AppArmorProfile{ObjectMeta: objectMeta("unused")}
	unusedRaw := &selinuxprofileapi.RawSelinuxProfile{ObjectMeta: objectMeta("unused-raw")}

	var listed []string

	r, c, _ := newAnnotator(t, &interceptor.Funcs{
		List: func(
			ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption,
		) error {
			if err := cl.List(ctx, list, opts...); err != nil {
				return err
			}

			switch l := list.(type) {
			case *apparmorprofileapi.AppArmorProfileList:
				for i := range l.Items {
					listed = append(listed, l.Items[i].Name)
				}
			case *selinuxprofileapi.RawSelinuxProfileList:
				for i := range l.Items {
					listed = append(listed, l.Items[i].Name)
				}
			}

			return nil
		},
	}, inUse, unused, unusedRaw)

	require.NoError(t, reconcilePod(t, r))
	require.Equal(t, []string{"in-use"}, listed)
	requireInUse(t, c, inUse, false)
}

func TestInUseIndex(t *testing.T) {
	t.Parallel()

	require.Equal(t, []string{inUseValue}, inUseIndex(&apparmorprofileapi.AppArmorProfile{
		ObjectMeta: objectMeta("in-use", util.HasActivePodsFinalizerString),
	}))
	require.Empty(t, inUseIndex(&selinuxprofileapi.RawSelinuxProfile{
		ObjectMeta: objectMeta("unused", "other-finalizer"),
	}))
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
