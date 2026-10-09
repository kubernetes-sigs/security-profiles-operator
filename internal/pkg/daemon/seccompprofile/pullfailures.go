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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"

	spodapi "sigs.k8s.io/security-profiles-operator/api/spod/v1"
)

const (
	// initialPullBackoff is the time after which a base profile is pulled
	// again after its first failed pull.
	initialPullBackoff = 10 * time.Second

	// maxPullBackoff limits the time between the pulls of a base profile
	// which keeps failing.
	maxPullBackoff = 5 * time.Minute
)

// errPullBackoff is returned for a base profile whose last pull failed, until
// it gets pulled again.
var errPullBackoff = errors.New("the last pull of the base profile failed")

// pullFailures remembers the failed pulls of OCI base profiles. Without it,
// every profile pulls its base profile again on every resync of the daemon and
// on every retry of the controller, on every node, while the registry is down.
// A failed reference is pulled again after a backoff, which doubles with each
// failure up to maxPullBackoff. The failures are kept per pull configuration,
// so that a fixed configuration gets pulled right away. The zero value is
// ready to use.
type pullFailures struct {
	mu       sync.Mutex
	failures map[pullKey]*pullFailure
	// now returns the current time, which tests override.
	now func() time.Time
}

// pullKey identifies the pulls of a reference with a configuration.
type pullKey struct {
	ref string
	// config identifies the pull settings of the SPOD, see newPullKey.
	config string
}

// newPullKey returns the key of the pulls of ref with the pull settings of the
// SPOD. The Secret and the ConfigMap the settings refer to are part of it by
// name only: reading them on every check would read them uncached on every
// resync, a change of their content is picked up with the next pull.
func newPullKey(ref string, security *spodapi.SPODSecurityConfig) pullKey {
	// The defaults of the regexps match everything, like when they are unset.
	defaulted := func(regexp string) string {
		if regexp == "" {
			return allowedAllRegexp
		}

		return regexp
	}

	settings, err := json.Marshal(struct {
		Disable               *bool                              `json:"disable,omitempty"`
		Identity              string                             `json:"identity,omitempty"`
		Issuer                string                             `json:"issuer,omitempty"`
		SignatureVerification *spodapi.SPODSignatureVerification `json:"signatureVerification,omitempty"`
	}{
		security.DisableOCIArtifactSignatureVerification,
		defaulted(security.AllowedIdentityRegexp),
		defaulted(security.AllowedOidcIssuerRegexp),
		security.SignatureVerification,
	})
	if err != nil {
		// Cannot happen for these types. Without a config, the failures
		// are kept like for a configuration which never changes.
		return pullKey{ref: ref}
	}

	sum := sha256.Sum256(settings)

	return pullKey{ref: ref, config: hex.EncodeToString(sum[:])}
}

// pullFailure is the last failed pull of a reference.
type pullFailure struct {
	err     error
	backoff time.Duration
	retryAt time.Time
	// reported holds the profiles which got the failure reported.
	reported sets.Set[types.NamespacedName]
}

func (p *pullFailures) currentTime() time.Time {
	if p.now != nil {
		return p.now()
	}

	return time.Now()
}

// check returns an error wrapping the error of the last pull of key if it is
// not to be pulled again yet.
func (p *pullFailures) check(key pullKey) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	failure, ok := p.failures[key]
	if !ok || !p.currentTime().Before(failure.retryAt) {
		return nil
	}

	return fmt.Errorf(
		"%w, pulling %s again after %s: %w",
		errPullBackoff, key.ref, failure.retryAt.Format(time.RFC3339), failure.err,
	)
}

// failed records a failed pull of key, which got reported for the profile
// which pulled it.
func (p *pullFailures) failed(key pullKey, err error, profile types.NamespacedName) {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := p.currentTime()

	// A failure long after the previous one starts the backoff over, and
	// the references which did not fail for that long are forgotten, so that
	// the ones which are not used anymore do not pile up.
	for r, failure := range p.failures {
		if now.Sub(failure.retryAt) > maxPullBackoff {
			delete(p.failures, r)
		}
	}

	if p.failures == nil {
		p.failures = map[pullKey]*pullFailure{}
	}

	failure, ok := p.failures[key]
	if !ok {
		failure = &pullFailure{}
		p.failures[key] = failure
	}

	failure.backoff = min(max(2*failure.backoff, initialPullBackoff), maxPullBackoff)
	failure.err = err
	failure.retryAt = now.Add(failure.backoff)
	failure.reported = sets.New(profile)
}

// report reports whether the last failed pull of key still has to be reported
// for the profile, which then counts as reported. The other profiles with the
// same base profile do not pull it during the backoff, but get the failure
// reported once all the same.
func (p *pullFailures) report(key pullKey, profile types.NamespacedName) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	failure, ok := p.failures[key]
	if !ok || failure.reported.Has(profile) {
		return false
	}

	failure.reported.Insert(profile)

	return true
}

// succeeded forgets the failed pulls of key.
func (p *pullFailures) succeeded(key pullKey) {
	p.mu.Lock()
	defer p.mu.Unlock()

	delete(p.failures, key)
}
