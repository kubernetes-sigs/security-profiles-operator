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

package signing

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	prototrustroot "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/stretchr/testify/require"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/artifact"
)

func service(url string, version uint32) []root.Service {
	return []root.Service{
		{URL: url, MajorAPIVersion: version, ValidityPeriodStart: time.Now().Add(-time.Hour)},
	}
}

// testSigningConfig returns a signing config with the Fulcio instance, a
// Rekor log of the version and a timestamp authority if tsa is set.
func testSigningConfig(
	t *testing.T, fulcioURL string, rekorVersion uint32, tsa bool,
) *root.SigningConfig {
	t.Helper()

	any1 := root.ServiceConfiguration{Selector: prototrustroot.ServiceSelector_ANY, Count: 1}

	var authorities []root.Service
	if tsa {
		authorities = service("https://tsa.example.com", 1)
	}

	signingConfig, err := root.NewSigningConfig(
		root.SigningConfigMediaType02,
		service(fulcioURL, 1),
		service("https://oauth2.example.com", 1),
		service("https://rekor.example.com", rekorVersion),
		any1, authorities, any1,
	)
	require.NoError(t, err)

	return signingConfig
}

func TestBundleOptions(t *testing.T) {
	t.Parallel()

	config := func(t *testing.T, rekorVersion uint32, tsa bool) *root.SigningConfig {
		t.Helper()

		return testSigningConfig(t, "https://fulcio.example.com", rekorVersion, tsa)
	}

	opts, err := bundleOptions(config(t, 1, false), nil, "token")
	require.NoError(t, err)
	require.NotNil(t, opts.CertificateProvider)
	require.Equal(t, "token", opts.CertificateProviderOptions.IDToken)
	require.Len(t, opts.TransparencyLogs, 1)
	require.Empty(t, opts.TimestampAuthorities)

	opts, err = bundleOptions(config(t, 2, true), nil, "token")
	require.NoError(t, err)
	require.Len(t, opts.TransparencyLogs, 1)
	require.Len(t, opts.TimestampAuthorities, 1)

	_, err = bundleOptions(config(t, 2, false), nil, "token")
	require.ErrorIs(t, err, artifact.ErrRekorV2WithoutTimestampAuthority)
}

// TestDSSESigner verifies that the signing function of DSSESigner requests
// the certificate from the Fulcio instance of the signing config with the
// identity token.
func TestDSSESigner(t *testing.T) {
	t.Parallel()

	var requests atomic.Int32

	fulcio := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)

		if r.Header.Get("Authorization") != "Bearer "+testToken {
			t.Errorf("unexpected authorization %q", r.Header.Get("Authorization"))
		}

		w.WriteHeader(http.StatusBadRequest)
	}))
	t.Cleanup(fulcio.Close)

	_, err := New().DSSESigner(testSigningConfig(t, fulcio.URL, 2, false), nil, testToken)
	require.ErrorIs(t, err, artifact.ErrRekorV2WithoutTimestampAuthority)

	signDSSE, err := New().DSSESigner(testSigningConfig(t, fulcio.URL, 1, false), nil, testToken)
	require.NoError(t, err)

	_, err = signDSSE(t.Context(), []byte("payload"), "application/vnd.in-toto+json")
	require.Error(t, err)
	require.Positive(t, requests.Load())
}

// testToken is an identity token whose subject Fulcio clients read without
// verifying it.
var testToken = "header." +
	base64.RawURLEncoding.EncodeToString(
		[]byte(`{"sub":"signer@example.com","iss":"https://issuer"}`),
	) +
	".signature"
