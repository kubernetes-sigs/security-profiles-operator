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

package seccompprofile

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"

	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	spodapi "sigs.k8s.io/security-profiles-operator/api/spod/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/artifact"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/seccompprofile/seccompprofilefakes"
)

func TestPullFailures(t *testing.T) {
	t.Parallel()

	now := time.Unix(1000, 0)
	p := &pullFailures{now: func() time.Time { return now }}
	errPull := errors.New("registry down")
	key := func(ref string) pullKey { return pullKey{ref: ref} }
	profile := types.NamespacedName{Name: "profile"}

	require.NoError(t, p.check(key("ref")), "a reference which never failed is pulled")

	// The backoff doubles with each failure up to the maximum.
	for _, backoff := range []time.Duration{
		10 * time.Second, 20 * time.Second, 40 * time.Second, 80 * time.Second,
		160 * time.Second, maxPullBackoff, maxPullBackoff,
	} {
		p.failed(key("ref"), errPull, profile)

		err := p.check(key("ref"))
		require.ErrorIs(t, err, errPullBackoff)
		require.ErrorIs(t, err, errPull, "the error of the failed pull is kept")
		require.NoError(t, p.check(key("other")), "other references are not affected")

		now = now.Add(backoff - time.Second)

		require.Error(t, p.check(key("ref")))

		now = now.Add(time.Second)

		require.NoError(t, p.check(key("ref")))
	}

	// A successful pull forgets the failures.
	p.failed(key("ref"), errPull, profile)
	p.succeeded(key("ref"))
	require.NoError(t, p.check(key("ref")))
	require.Empty(t, p.failures)

	// A failure long after the previous one starts the backoff over, and
	// the references which did not fail for that long are forgotten.
	p.failed(key("ref"), errPull, profile)
	p.failed(key("unused"), errPull, profile)

	now = now.Add(time.Hour)

	p.failed(key("ref"), errPull, profile)
	require.Len(t, p.failures, 1)
	require.Equal(t, initialPullBackoff, p.failures[key("ref")].backoff)

	// The failure is reported once per profile, the one which pulled it got
	// it reported already. Another failure is reported again.
	other := types.NamespacedName{Name: "other"}

	require.False(t, p.report(key("ref"), profile))
	require.True(t, p.report(key("ref"), other))
	require.False(t, p.report(key("ref"), other))
	require.False(t, p.report(key("never failed"), other))

	now = now.Add(initialPullBackoff)

	p.failed(key("ref"), errPull, profile)
	require.False(t, p.report(key("ref"), profile))
	require.True(t, p.report(key("ref"), other))
}

// TestNewPullKey asserts that the pull key changes with the pull settings of
// the SPOD only.
func TestNewPullKey(t *testing.T) {
	t.Parallel()

	unset := newPullKey("ref", &spodapi.SPODSecurityConfig{})

	require.Equal(t, "ref", unset.ref)
	require.Equal(t, unset, newPullKey("ref", &spodapi.SPODSecurityConfig{
		AllowedIdentityRegexp:   allowedAllRegexp,
		AllowedOidcIssuerRegexp: allowedAllRegexp,
		AllowedSyscalls:         []string{"read"},
	}), "the defaults and other settings do not change the key")

	for name, security := range map[string]*spodapi.SPODSecurityConfig{
		"disabled verification": {DisableOCIArtifactSignatureVerification: new(true)},
		"identity":              {AllowedIdentityRegexp: "identity"},
		"issuer":                {AllowedOidcIssuerRegexp: "issuer"},
		"signature verification": {SignatureVerification: &spodapi.SPODSignatureVerification{
			AllowedIdentity: "identity",
		}},
	} {
		require.NotEqual(t, unset, newPullKey("ref", security), name)
	}

	require.NotEqual(t, unset, newPullKey("other", &spodapi.SPODSecurityConfig{}))
}

// A failed pull of an OCI base profile is not repeated by every resync and
// retry of the controller, and it is reported once per profile.
func TestPullBaseProfileBacksOff(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		prepare func(*seccompprofilefakes.FakeImpl)
		assert  func(*testing.T, error)
		events  int
	}{
		"registry unreachable": {
			prepare: func(mock *seccompprofilefakes.FakeImpl) {
				mock.PullReturns(nil, errTest)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()
				require.ErrorIs(t, err, errTest)
				require.NotErrorIs(t, err, errInvalidBaseProfile, "a failed pull is retried")
			},
			events: 1,
		},
		"not a seccomp profile": {
			prepare: func(mock *seccompprofilefakes.FakeImpl) {
				mock.PullResultTypeReturns(artifact.PullResultTypeSelinuxProfile)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()
				require.ErrorIs(t, err, errInvalidBaseProfile, "the profile is still rejected")
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			mock := &seccompprofilefakes.FakeImpl{}
			mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{}, nil)
			tc.prepare(mock)

			sut, ok := NewController().(*Reconciler)
			require.True(t, ok)

			now := time.Unix(1000, 0)
			recorder := events.NewFakeRecorder(10)
			sut.impl = mock
			sut.metrics = metrics.New()
			sut.record = recorder
			sut.pullFailures.now = func() time.Time { return now }

			sp := &seccompprofileapi.SeccompProfile{
				Spec: seccompprofileapi.SeccompProfileSpec{
					BaseProfileName: config.OCIProfilePrefix + "registry/base:v1",
				},
			}

			resolve := func() error {
				_, _, err := sut.resolveSyscallsForProfile(
					t.Context(), sp, sp.Spec.Syscalls, logr.Discard(), 0,
				)

				return err
			}

			for range 3 {
				err := resolve()
				tc.assert(t, err)
			}

			require.Equal(t, 1, mock.PullCallCount())
			require.Len(t, recorder.Events, tc.events)

			// The pull is retried after the backoff, and a successful one
			// gets cached as usual.
			now = now.Add(initialPullBackoff)

			mock.PullReturns(nil, nil)
			mock.PullResultTypeReturns(artifact.PullResultTypeSeccompProfile)
			mock.PullResultSeccompProfileReturns(&seccompprofileapi.SeccompProfile{})

			require.NoError(t, resolve())
			require.NoError(t, resolve())
			require.Equal(t, 2, mock.PullCallCount())
			require.Empty(t, sut.pullFailures.failures)
		})
	}
}

// TestPullBaseProfileReportsBackoffPerProfile asserts that a profile which
// shares a base profile, whose pull failed for another profile, gets the
// failure reported once during the backoff.
func TestPullBaseProfileReportsBackoffPerProfile(t *testing.T) {
	t.Parallel()

	mock := &seccompprofilefakes.FakeImpl{}
	mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{}, nil)
	mock.PullReturns(nil, errTest)

	sut, ok := NewController().(*Reconciler)
	require.True(t, ok)

	recorder := events.NewFakeRecorder(10)
	sut.impl = mock
	sut.metrics = metrics.New()
	sut.record = recorder

	resolve := func(name string) error {
		t.Helper()

		sp := &seccompprofileapi.SeccompProfile{}
		sp.Name = name
		sp.Spec.BaseProfileName = config.OCIProfilePrefix + "registry/base:v1"

		_, _, err := sut.resolveSyscallsForProfile(
			t.Context(), sp, sp.Spec.Syscalls, logr.Discard(), 0,
		)

		return err
	}

	require.ErrorIs(t, resolve("a"), errTest)
	require.Len(t, recorder.Events, 1)
	<-recorder.Events

	for range 2 {
		require.ErrorIs(t, resolve("a"), errPullBackoff)
		require.ErrorIs(t, resolve("b"), errPullBackoff)
	}

	require.Equal(t, 1, mock.PullCallCount())
	require.Len(t, recorder.Events, 1, "b gets the failure reported once")
	require.Contains(t, <-recorder.Events, errTest.Error())
}

// TestPullBaseProfileConfigChange asserts that a base profile gets pulled again
// right away once the pull settings of the SPOD changed, like after fixing the
// identity which failed the signature verification.
func TestPullBaseProfileConfigChange(t *testing.T) {
	t.Parallel()

	spod := &spodapi.SecurityProfilesOperatorDaemon{}
	spod.Spec.Security.AllowedIdentityRegexp = "wrong"

	mock := &seccompprofilefakes.FakeImpl{}
	mock.GetSPODCalls(func(
		context.Context, client.Client, string,
	) (*spodapi.SecurityProfilesOperatorDaemon, error) {
		return spod.DeepCopy(), nil
	})
	mock.PullReturns(nil, artifact.ErrSignatureVerification)

	sut, ok := NewController().(*Reconciler)
	require.True(t, ok)

	now := time.Unix(1000, 0)
	sut.impl = mock
	sut.metrics = metrics.New()
	sut.record = events.NewFakeRecorder(10)
	sut.pullFailures.now = func() time.Time { return now }

	sp := &seccompprofileapi.SeccompProfile{
		Spec: seccompprofileapi.SeccompProfileSpec{
			BaseProfileName: config.OCIProfilePrefix + "registry/base:v1",
		},
	}

	resolve := func() error {
		_, _, err := sut.resolveSyscallsForProfile(
			t.Context(), sp, sp.Spec.Syscalls, logr.Discard(), 0,
		)

		return err
	}

	require.ErrorIs(t, resolve(), artifact.ErrSignatureVerification)
	require.ErrorIs(t, resolve(), errPullBackoff)
	require.Equal(t, 1, mock.PullCallCount())

	// Settings which do not affect the pull keep the backoff.
	spod.Spec.Security.AllowedSyscalls = []string{"read"}

	require.ErrorIs(t, resolve(), errPullBackoff)
	require.Equal(t, 1, mock.PullCallCount())

	spod.Spec.Security.AllowedIdentityRegexp = "right"

	mock.PullReturns(nil, nil)
	mock.PullResultTypeReturns(artifact.PullResultTypeSeccompProfile)
	mock.PullResultSeccompProfileReturns(&seccompprofileapi.SeccompProfile{})

	require.NoError(t, resolve())
	require.Equal(t, 2, mock.PullCallCount())

	opts, ok := mock.Invocations()["Pull"][1][6].(*artifact.PullOptions)
	require.True(t, ok)
	require.Equal(t, "right", opts.AllowedIdentityRegexp)
}
