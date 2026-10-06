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

package artifact

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	prototrustroot "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"github.com/sigstore/rekor/pkg/pki"
	rekortypes "github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/tlog"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"oras.land/oras-go/v2"
	orascontent "oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry/remote"
)

const (
	testIdentity = "signer@example.com"
	testIssuer   = "https://issuer.example.com"
)

// testSigstore is a Sigstore instance of its own, a Fulcio CA and a Rekor
// log, so that signing and verification work without the public instance.
// Its trusted root has no certificate transparency log, the certificates it
// issues carry no certificate timestamps.
type testSigstore struct {
	vs              *ca.VirtualSigstore
	fulcio          *root.FulcioCertificateAuthority
	fulcioKey       *ecdsa.PrivateKey
	trustedRoot     *root.TrustedRoot
	trustedRootPath string
}

func newTestSigstore(t *testing.T) *testSigstore {
	t.Helper()

	vs, err := ca.NewVirtualSigstore()
	require.NoError(t, err)

	rootCert, rootKey, err := ca.GenerateRootCa()
	require.NoError(t, err)

	intermediate, intermediateKey, err := ca.GenerateFulcioIntermediate(rootCert, rootKey)
	require.NoError(t, err)

	fulcio := &root.FulcioCertificateAuthority{
		Root:                rootCert,
		Intermediates:       []*x509.Certificate{intermediate},
		ValidityPeriodStart: time.Now().Add(-time.Hour),
		ValidityPeriodEnd:   time.Now().Add(time.Hour),
		URI:                 "https://fulcio.example.com",
	}

	virtualFulcio, ok := vs.FulcioCertificateAuthorities()[0].(*root.FulcioCertificateAuthority)
	require.True(t, ok)

	// The virtual instance identifies its log by the hex encoded ID, a
	// trusted root file by the raw one.
	logs := map[string]*root.TransparencyLog{}

	for logID, rekor := range vs.RekorLogs() {
		rawID, err := hex.DecodeString(logID)
		require.NoError(t, err)

		rekorLog := *rekor
		rekorLog.ID = rawID
		logs[logID] = &rekorLog
	}

	trustedRoot, err := root.NewTrustedRoot(
		root.TrustedRootMediaType01,
		[]root.CertificateAuthority{fulcio, virtualFulcio},
		map[string]*root.TransparencyLog{},
		[]root.TimestampingAuthority{},
		logs,
	)
	require.NoError(t, err)

	raw, err := trustedRoot.MarshalJSON()
	require.NoError(t, err)

	trustedRootPath := filepath.Join(t.TempDir(), "trusted_root.json")
	require.NoError(t, os.WriteFile(trustedRootPath, raw, 0o600))

	// The file is what the pulls verify with, so it has to hold the same.
	_, err = root.NewTrustedRootFromPath(trustedRootPath)
	require.NoError(t, err)

	return &testSigstore{
		vs:              vs,
		fulcio:          fulcio,
		fulcioKey:       intermediateKey,
		trustedRoot:     trustedRoot,
		trustedRootPath: trustedRootPath,
	}
}

// logEntry creates the transparency log entry of the Rekor log, with an
// inclusion promise like Rekor v1 returns it.
func (s *testSigstore) logEntry(
	t *testing.T, kind, version string, props *rekortypes.ArtifactProperties,
) *protorekor.TransparencyLogEntry {
	t.Helper()

	return s.logEntryWithProof(t.Context(), t, kind, version, props, false)
}

// logEntryWithProof creates the transparency log entry of the Rekor log with
// an inclusion promise and optionally an inclusion proof, both of which
// Rekor v1 returns and signature bundles v0.3 require.
func (s *testSigstore) logEntryWithProof(
	ctx context.Context,
	t *testing.T, kind, version string, props *rekortypes.ArtifactProperties, withProof bool,
) *protorekor.TransparencyLogEntry {
	t.Helper()

	proposed, err := rekortypes.NewProposedEntry(ctx, kind, version, *props)
	require.NoError(t, err)

	versioned, err := rekortypes.CreateVersionedEntry(proposed)
	require.NoError(t, err)

	body, err := rekortypes.CanonicalizeEntry(ctx, versioned)
	require.NoError(t, err)

	logID, err := s.vs.RekorLogID()
	require.NoError(t, err)

	logIDRaw, err := hex.DecodeString(logID)
	require.NoError(t, err)

	integratedTime := time.Now().Unix()

	set, err := s.vs.RekorSignPayload(tlog.RekorPayload{
		Body:           base64.StdEncoding.EncodeToString(body),
		IntegratedTime: integratedTime,
		LogIndex:       0,
		LogID:          logID,
	})
	require.NoError(t, err)

	entry := &protorekor.TransparencyLogEntry{
		LogIndex:          0,
		LogId:             &protocommon.LogId{KeyId: logIDRaw},
		KindVersion:       &protorekor.KindVersion{Kind: kind, Version: version},
		IntegratedTime:    integratedTime,
		InclusionPromise:  &protorekor.InclusionPromise{SignedEntryTimestamp: set},
		CanonicalizedBody: body,
	}

	if withProof {
		proof, err := s.vs.GetInclusionProof(body)
		require.NoError(t, err)

		rootHash, err := hex.DecodeString(*proof.RootHash)
		require.NoError(t, err)

		hashes := make([][]byte, 0, len(proof.Hashes))

		for _, hash := range proof.Hashes {
			raw, err := hex.DecodeString(hash)
			require.NoError(t, err)

			hashes = append(hashes, raw)
		}

		entry.InclusionProof = &protorekor.InclusionProof{
			LogIndex:   *proof.LogIndex,
			RootHash:   rootHash,
			TreeSize:   *proof.TreeSize,
			Hashes:     hashes,
			Checkpoint: &protorekor.Checkpoint{Envelope: *proof.Checkpoint},
		}
	}

	return entry
}

// publicSigner only has the public key the leaf certificate is issued for.
type publicSigner struct {
	public crypto.PublicKey
}

var errNoPrivateKey = errors.New("no private key")

func (p publicSigner) Public() crypto.PublicKey {
	return p.public
}

func (publicSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errNoPrivateKey
}

// testFulcio issues certificates for a fixed identity.
type testFulcio struct {
	sigstore         *testSigstore
	identity, issuer string
}

func (f *testFulcio) GetCertificate(
	_ context.Context, keypair sign.Keypair, _ *sign.CertificateProviderOptions,
) ([]byte, error) {
	cert, err := ca.GenerateLeafCert(
		f.identity, f.issuer, time.Now().Add(-time.Minute),
		publicSigner{keypair.GetPublicKey()},
		f.sigstore.fulcio.Intermediates[0], f.sigstore.fulcioKey,
	)
	if err != nil {
		return nil, err
	}

	return cert.Raw, nil
}

// testRekor logs DSSE envelopes in the Rekor log of the test instance.
type testRekor struct {
	t        *testing.T
	sigstore *testSigstore
}

func (r *testRekor) GetTransparencyLogEntry(
	ctx context.Context, keyOrCertPEM []byte, bundle *protobundle.Bundle,
) error {
	envelope, err := protojson.Marshal(bundle.GetDsseEnvelope())
	if err != nil {
		return err
	}

	entry := r.sigstore.logEntryWithProof(ctx, r.t, "dsse", "0.0.1", &rekortypes.ArtifactProperties{
		ArtifactBytes:  envelope,
		PublicKeyBytes: [][]byte{keyOrCertPEM},
		PKIFormat:      string(pki.X509),
	}, true)

	material := bundle.GetVerificationMaterial()
	material.TlogEntries = append(material.GetTlogEntries(), entry)

	return nil
}

// testSigningConfig is a signing config with a Fulcio instance, an OIDC
// provider and a Rekor v1 log.
func testSigningConfig(t *testing.T) *root.SigningConfig {
	t.Helper()

	service := func(url string) []root.Service {
		return []root.Service{
			{URL: url, MajorAPIVersion: 1, ValidityPeriodStart: time.Now().Add(-time.Hour)},
		}
	}

	config, err := root.NewSigningConfig(
		root.SigningConfigMediaType02,
		service("https://fulcio.example.com"),
		service("https://oauth2.example.com"),
		service("https://rekor.example.com"),
		root.ServiceConfiguration{Selector: prototrustroot.ServiceSelector_ANY, Count: 1},
		nil,
		root.ServiceConfiguration{},
	)
	require.NoError(t, err)

	return config
}

// testSigstoreImpl signs and verifies with the test instance instead of the
// public Sigstore instance, everything else is the default implementation.
type testSigstoreImpl struct {
	defaultImpl

	t        *testing.T
	sigstore *testSigstore
	identity string
}

func (i *testSigstoreImpl) TrustedMaterial(
	ctx context.Context, trustedRootPath string, offline bool,
) (root.TrustedMaterial, error) {
	if trustedRootPath == "" {
		return i.sigstore.trustedRoot, nil
	}

	return i.defaultImpl.TrustedMaterial(ctx, trustedRootPath, offline)
}

func (i *testSigstoreImpl) SigningConfig(context.Context) (*root.SigningConfig, error) {
	return testSigningConfig(i.t), nil
}

func (*testSigstoreImpl) IDToken(context.Context, string, bool) (string, error) {
	return "token", nil
}

func (i *testSigstoreImpl) SignBundle(
	ctx context.Context, content sign.Content, opts *sign.BundleOptions,
) (*protobundle.Bundle, error) {
	require.NotNil(i.t, opts.CertificateProvider)
	require.Equal(i.t, "token", opts.CertificateProviderOptions.IDToken)
	require.Len(i.t, opts.TransparencyLogs, 1)

	testOpts := *opts
	testOpts.CertificateProvider = &testFulcio{
		sigstore: i.sigstore,
		identity: i.identity,
		issuer:   testIssuer,
	}
	testOpts.TransparencyLogs = []sign.Transparency{&testRekor{t: i.t, sigstore: i.sigstore}}

	return i.defaultImpl.SignBundle(ctx, content, &testOpts)
}

// testRegistry starts an in-process registry and returns its host.
func testRegistry(t *testing.T, referrersAPI bool) string {
	t.Helper()

	server := httptest.NewServer(registry.New(
		registry.WithReferrersSupport(referrersAPI),
		registry.Logger(log.New(io.Discard, "", 0)),
	))
	t.Cleanup(server.Close)

	return strings.TrimPrefix(server.URL, "http://")
}

// testRepository returns the repository of the in-process registry.
func testRepository(t *testing.T, host, name string) *remote.Repository {
	t.Helper()

	repo, err := remote.NewRepository(host + "/" + name)
	require.NoError(t, err)

	repo.PlainHTTP = true

	return repo
}

// pushUnsigned pushes a profile without signature and returns the descriptor
// of its manifest.
func pushUnsigned(t *testing.T, sut *Artifact, host, name string) ocispec.Descriptor {
	t.Helper()

	profile := filepath.Join(t.TempDir(), "profile.yaml")
	require.NoError(t, os.WriteFile(profile, []byte(
		"apiVersion: security-profiles-operator.x-k8s.io/v1\nkind: SeccompProfile\n"+
			"metadata:\n  name: "+name+"\nspec:\n  defaultAction: SCMP_ACT_ERRNO\n",
	), 0o600))
	require.NoError(t, sut.Push(t.Context(),
		map[*ocispec.Platform]string{nil: profile},
		host+"/"+name+":v1", "", "", nil, &PushOptions{DisableSigning: true, PlainHTTP: true},
	))

	desc, err := testRepository(t, host, name).Resolve(t.Context(), "v1")
	require.NoError(t, err)

	return desc
}

// writePublicKey writes the public key as PEM file.
func writePublicKey(t *testing.T, publicKey crypto.PublicKey) string {
	t.Helper()

	raw, err := cryptoutils.MarshalPublicKeyToPEM(publicKey)
	require.NoError(t, err)

	keyPath := filepath.Join(t.TempDir(), "cosign.pub")
	require.NoError(t, os.WriteFile(keyPath, raw, 0o600))

	return keyPath
}

// legacyPayload is the simple signing payload cosign v2 signs for a digest.
func legacyPayload(t *testing.T, reference string, subject digest.Digest) []byte {
	t.Helper()

	raw, err := json.Marshal(map[string]any{
		"critical": map[string]any{
			"identity": map[string]string{"docker-reference": reference},
			"image":    map[string]string{"docker-manifest-digest": subject.String()},
			"type":     "cosign container image signature",
		},
		"optional": nil,
	})
	require.NoError(t, err)

	return raw
}

// rekorBundleAnnotation returns the transparency log annotation of a legacy
// signature for the log entry.
func rekorBundleAnnotation(t *testing.T, entry *protorekor.TransparencyLogEntry) string {
	t.Helper()

	raw, err := json.Marshal(map[string]any{
		"SignedEntryTimestamp": entry.GetInclusionPromise().GetSignedEntryTimestamp(),
		"Payload": map[string]any{
			"body":           entry.GetCanonicalizedBody(),
			"integratedTime": entry.GetIntegratedTime(),
			"logIndex":       entry.GetLogIndex(),
			"logID":          hex.EncodeToString(entry.GetLogId().GetKeyId()),
		},
	})
	require.NoError(t, err)

	return string(raw)
}

// keylessLegacySignature signs the payload like cosign v2 signs keylessly
// and returns the layer annotations.
func (s *testSigstore) keylessLegacySignature(
	t *testing.T, signedPayload []byte, identity string,
) map[string]string {
	t.Helper()

	entity, err := s.vs.Sign(identity, testIssuer, signedPayload)
	require.NoError(t, err)

	content, err := entity.VerificationContent()
	require.NoError(t, err)

	certPEM, err := cryptoutils.MarshalCertificateToPEM(content.Certificate())
	require.NoError(t, err)

	sigContent, err := entity.SignatureContent()
	require.NoError(t, err)

	entry := s.logEntry(t, "hashedrekord", "0.0.1", &rekortypes.ArtifactProperties{
		ArtifactHash:   sha256Hex(signedPayload),
		SignatureBytes: sigContent.Signature(),
		PublicKeyBytes: [][]byte{certPEM},
		PKIFormat:      string(pki.X509),
	})

	return map[string]string{
		annotationLegacySignature:   base64.StdEncoding.EncodeToString(sigContent.Signature()),
		annotationLegacyCertificate: string(certPEM),
		annotationLegacyBundle:      rekorBundleAnnotation(t, entry),
	}
}

// keyLegacySignature signs the payload like `cosign sign --key` of cosign v2
// and returns the layer annotations.
func (s *testSigstore) keyLegacySignature(
	t *testing.T, signedPayload []byte, key *ecdsa.PrivateKey,
) map[string]string {
	t.Helper()

	signer, err := signature.LoadECDSASignerVerifier(key, crypto.SHA256)
	require.NoError(t, err)

	sig, err := signer.SignMessage(bytes.NewReader(signedPayload))
	require.NoError(t, err)

	publicKeyPEM, err := cryptoutils.MarshalPublicKeyToPEM(key.Public())
	require.NoError(t, err)

	entry := s.logEntry(t, "hashedrekord", "0.0.1", &rekortypes.ArtifactProperties{
		ArtifactHash:   sha256Hex(signedPayload),
		SignatureBytes: sig,
		PublicKeyBytes: [][]byte{publicKeyPEM},
		PKIFormat:      string(pki.X509),
	})

	return map[string]string{
		annotationLegacySignature: base64.StdEncoding.EncodeToString(sig),
		annotationLegacyBundle:    rekorBundleAnnotation(t, entry),
	}
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)

	return hex.EncodeToString(sum[:])
}

// attachLegacySignatures attaches the signatures to the subject like cosign
// v2 does: one layer per signature in the manifest tagged after the digest.
func attachLegacySignatures(
	t *testing.T, repo *remote.Repository, subject digest.Digest,
	signedPayload []byte, annotations ...map[string]string,
) {
	t.Helper()

	layers := make([]ocispec.Descriptor, 0, len(annotations))

	for _, layerAnnotations := range annotations {
		layer := orascontent.NewDescriptorFromBytes(
			"application/vnd.dev.cosign.simplesigning.v1+json", signedPayload,
		)
		require.NoError(t, repo.Push(t.Context(), layer, bytes.NewReader(signedPayload)))

		layer.Annotations = layerAnnotations
		layers = append(layers, layer)
	}

	manifest, err := oras.PackManifest(
		t.Context(), repo, oras.PackManifestVersion1_0, "application/vnd.oci.image.config.v1+json",
		oras.PackManifestOptions{Layers: layers},
	)
	require.NoError(t, err)
	require.NoError(t, repo.Tag(
		t.Context(),
		manifest,
		subject.Algorithm().String()+"-"+subject.Encoded()+legacySignatureTagSuffix,
	))
}

// keyBundle signs the subject with an ephemeral key into a signature bundle
// logged in the Rekor log of the test instance, like `cosign sign --key`
// does. It returns the bundle and the public key file.
func (s *testSigstore) keyBundle(
	t *testing.T, subject digest.Digest, predicateType string,
) (bundle []byte, publicKeyPath string) {
	t.Helper()

	statement, err := signatureStatement(subject)
	require.NoError(t, err)

	if predicateType != cosignSignPredicateType {
		statement = bytes.Replace(
			statement, []byte(cosignSignPredicateType), []byte(predicateType), 1,
		)
	}

	keypair, err := sign.NewEphemeralKeypair(nil)
	require.NoError(t, err)

	signed, err := sign.Bundle(
		&sign.DSSEData{Data: statement, PayloadType: inTotoPayloadType}, keypair,
		sign.BundleOptions{TransparencyLogs: []sign.Transparency{&testRekor{t: t, sigstore: s}}},
	)
	require.NoError(t, err)

	bundle, err = protojson.Marshal(signed)
	require.NoError(t, err)

	return bundle, writePublicKey(t, keypair.GetPublicKey())
}

// TestSignAndVerify signs a pushed artifact keylessly and verifies it on
// pull, with and without the referrers API of the registry.
func TestSignAndVerify(t *testing.T) {
	t.Parallel()

	for _, referrersAPI := range []bool{true, false} {
		t.Run(
			map[bool]string{true: "referrers API", false: "referrers tag"}[referrersAPI],
			func(t *testing.T) {
				t.Parallel()

				host := testRegistry(t, referrersAPI)
				sigstore := newTestSigstore(t)

				sut := New(logr.Discard())
				sut.impl = &testSigstoreImpl{t: t, sigstore: sigstore, identity: testIdentity}

				profile := filepath.Join(t.TempDir(), "profile.json")
				require.NoError(t, os.WriteFile(profile, []byte(rawSeccompJSON), 0o600))
				require.NoError(t, sut.Push(t.Context(),
					map[*ocispec.Platform]string{nil: profile},
					host+"/signed:v1", "", "", nil, &PushOptions{PlainHTTP: true},
				))

				repo := testRepository(t, host, "signed")
				subject, err := repo.Resolve(t.Context(), "v1")
				require.NoError(t, err)

				// The signature is a bundle referrer in the layout cosign writes.
				var referrers []ocispec.Descriptor

				require.NoError(
					t,
					repo.Referrers(t.Context(), subject, "", func(page []ocispec.Descriptor) error {
						referrers = append(referrers, page...)

						return nil
					}),
				)
				require.Len(t, referrers, 1)

				raw, err := orascontent.FetchAll(t.Context(), repo, referrers[0])
				require.NoError(t, err)

				var manifest ocispec.Manifest
				require.NoError(t, json.Unmarshal(raw, &manifest))
				require.Equal(t, bundleMediaType, manifest.ArtifactType)
				require.Equal(
					t,
					cosignSignPredicateType,
					manifest.Annotations[annotationBundlePredicateType],
				)
				require.Equal(t, bundleContentDSSE, manifest.Annotations[annotationBundleContent])
				require.Equal(t, subject.Digest, manifest.Subject.Digest)
				require.Len(t, manifest.Layers, 1)
				require.Equal(t, bundleMediaType, manifest.Layers[0].MediaType)

				otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)

				for _, tc := range []struct {
					name    string
					opts    PullOptions
					wantErr bool
				}{
					{name: "any signer", opts: PullOptions{}},
					{name: "exact signer", opts: PullOptions{CertIdentity: testIdentity, CertOidcIssuer: testIssuer}},
					{
						name: "signer regexps",
						opts: PullOptions{AllowedIdentityRegexp: `^signer@`, AllowedOidcIssuerRegexp: `example\.com$`},
					},
					{name: "other identity", opts: PullOptions{CertIdentity: "other@example.com"}, wantErr: true},
					{name: "other issuer", opts: PullOptions{AllowedOidcIssuerRegexp: "^https://other$"}, wantErr: true},
					{name: "key", opts: PullOptions{KeyRef: writePublicKey(t, otherKey.Public())}, wantErr: true},
				} {
					opts := tc.opts
					opts.PlainHTTP = true
					opts.TrustedRootPath = sigstore.trustedRootPath

					res, err := sut.Pull(t.Context(), host+"/signed:v1", "", "", nil, &opts)
					if tc.wantErr {
						require.ErrorContains(t, err, "verify signature", tc.name)
						require.Nil(t, res, tc.name)

						continue
					}

					require.NoError(t, err, tc.name)
					require.JSONEq(t, rawSeccompJSON, string(res.Content()), tc.name)
				}

				// A trusted root without the signing CA and log does not verify.
				_, err = sut.Pull(t.Context(), host+"/signed:v1", "", "", nil, &PullOptions{
					PlainHTTP: true, TrustedRootPath: newTestSigstore(t).trustedRootPath,
				})
				require.ErrorContains(t, err, "verify signature")
			},
		)
	}
}

// TestVerifyKeyBundle verifies a signature bundle made with a key.
func TestVerifyKeyBundle(t *testing.T) {
	t.Parallel()

	host := testRegistry(t, true)
	sigstore := newTestSigstore(t)
	sut := New(logr.Discard())
	subject := pushUnsigned(t, sut, host, "keyed")
	repo := testRepository(t, host, "keyed")

	bundle, publicKey := sigstore.keyBundle(t, subject.Digest, cosignSignPredicateType)
	require.NoError(t, sut.attachSignatureBundle(t.Context(), repo, &subject, bundle))

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pull := func(opts PullOptions) error {
		opts.PlainHTTP = true
		opts.TrustedRootPath = sigstore.trustedRootPath

		_, err := sut.Pull(t.Context(), host+"/keyed:v1", "", "", nil, &opts)

		return err
	}

	require.NoError(t, pull(PullOptions{KeyRef: publicKey}))
	require.ErrorContains(
		t,
		pull(PullOptions{KeyRef: writePublicKey(t, otherKey.Public())}),
		"verify signature",
	)
	// A key signature has no certificate to match an identity.
	require.ErrorContains(t, pull(PullOptions{}), "verify signature")
}

// TestVerifyLegacySignatures verifies the signature tags cosign v2 and older
// versions of this project write.
func TestVerifyLegacySignatures(t *testing.T) {
	t.Parallel()

	host := testRegistry(t, true)
	sigstore := newTestSigstore(t)
	sut := New(logr.Discard())

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	publicKey := writePublicKey(t, key.Public())

	for _, tc := range []struct {
		name        string
		annotations func(signedPayload []byte) []map[string]string
		opts        PullOptions
		otherDigest bool
		wantErr     error
	}{
		{
			name: "keyless",
			annotations: func(signedPayload []byte) []map[string]string {
				return []map[string]string{sigstore.keylessLegacySignature(t, signedPayload, testIdentity)}
			},
			opts: PullOptions{CertIdentity: testIdentity, CertOidcIssuer: testIssuer},
		},
		{
			name: "keyless with other signer first",
			annotations: func(signedPayload []byte) []map[string]string {
				return []map[string]string{
					sigstore.keylessLegacySignature(t, signedPayload, "other@example.com"),
					sigstore.keylessLegacySignature(t, signedPayload, testIdentity),
				}
			},
			opts: PullOptions{CertIdentity: testIdentity},
		},
		{
			name: "keyless with other identity",
			annotations: func(signedPayload []byte) []map[string]string {
				return []map[string]string{sigstore.keylessLegacySignature(t, signedPayload, "other@example.com")}
			},
			opts:    PullOptions{CertIdentity: testIdentity},
			wantErr: errors.New("verify signature"),
		},
		{
			name: "key",
			annotations: func(signedPayload []byte) []map[string]string {
				return []map[string]string{sigstore.keyLegacySignature(t, signedPayload, key)}
			},
			opts: PullOptions{KeyRef: publicKey},
		},
		{
			name: "key without transparency log entry",
			annotations: func(signedPayload []byte) []map[string]string {
				annotations := sigstore.keyLegacySignature(t, signedPayload, key)
				delete(annotations, annotationLegacyBundle)

				return []map[string]string{annotations}
			},
			opts:    PullOptions{KeyRef: publicKey},
			wantErr: errors.New("transparency log"),
		},
		{
			name: "signature of another digest",
			annotations: func(signedPayload []byte) []map[string]string {
				return []map[string]string{sigstore.keylessLegacySignature(t, signedPayload, testIdentity)}
			},
			otherDigest: true,
			wantErr:     ErrSignatureDigestMismatch,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			name := "legacy/" + strings.ReplaceAll(tc.name, " ", "-")
			subject := pushUnsigned(t, sut, host, name)
			repo := testRepository(t, host, name)

			signedDigest := subject.Digest
			if tc.otherDigest {
				signedDigest = digest.FromString("other")
			}

			signedPayload := legacyPayload(t, host+"/"+name, signedDigest)
			attachLegacySignatures(
				t,
				repo,
				subject.Digest,
				signedPayload,
				tc.annotations(signedPayload)...)

			opts := tc.opts
			opts.PlainHTTP = true
			opts.TrustedRootPath = sigstore.trustedRootPath

			res, err := sut.Pull(t.Context(), host+"/"+name+":v1", "", "", nil, &opts)
			if tc.wantErr != nil {
				require.Nil(t, res)
				require.ErrorContains(t, err, "verify signature")

				if errors.Is(tc.wantErr, ErrSignatureDigestMismatch) {
					require.ErrorIs(t, err, ErrSignatureDigestMismatch)
				} else {
					require.ErrorContains(t, err, tc.wantErr.Error())
				}

				return
			}

			require.NoError(t, err)
			require.NotNil(t, res)
		})
	}
}

// TestVerifyLegacySignatureBehindRedirects serves an artifact the way
// registry.k8s.io does: tag requests are redirected to the backend which holds
// the signatures, digest and blob requests to the closest mirror, which has
// the artifact and the blobs but not the manifests of the signature tags.
func TestVerifyLegacySignatureBehindRedirects(t *testing.T) {
	t.Parallel()

	primary := testRegistry(t, false)
	mirror := testRegistry(t, false)
	sigstore := newTestSigstore(t)
	sut := New(logr.Discard())

	subject := pushUnsigned(t, sut, primary, "redirect")
	require.Equal(t, subject, pushUnsigned(t, sut, mirror, "redirect"))

	signedPayload := legacyPayload(t, "registry.example.com/redirect", subject.Digest)
	attachLegacySignatures(
		t, testRepository(t, primary, "redirect"), subject.Digest, signedPayload,
		sigstore.keylessLegacySignature(t, signedPayload, testIdentity),
	)

	payloadDesc := orascontent.NewDescriptorFromBytes(
		"application/vnd.dev.cosign.simplesigning.v1+json", signedPayload,
	)
	require.NoError(t, testRepository(t, mirror, "redirect").Push(
		t.Context(), payloadDesc, bytes.NewReader(signedPayload),
	))

	var signatureTagRequests atomic.Int32

	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := mirror
		if strings.Contains(r.URL.Path, "/manifests/") &&
			!strings.Contains(path.Base(r.URL.Path), ":") {
			target = primary
		}

		if strings.HasSuffix(r.URL.Path, legacySignatureTagSuffix) {
			signatureTagRequests.Add(1)
		}

		//nolint:gosec // the test registries are the only targets
		http.Redirect(w, r, "http://"+target+r.URL.RequestURI(), http.StatusTemporaryRedirect)
	}))
	t.Cleanup(front.Close)

	host := strings.TrimPrefix(front.URL, "http://")

	res, err := sut.Pull(t.Context(), host+"/redirect:v1", "", "", nil, &PullOptions{
		PlainHTTP:       true,
		TrustedRootPath: sigstore.trustedRootPath,
		CertIdentity:    testIdentity,
		CertOidcIssuer:  testIssuer,
	})
	require.NoError(t, err)
	require.Equal(t, "redirect", res.SeccompProfile().GetName())

	// The signature manifest is fetched by tag in a single request.
	require.Equal(t, int32(1), signatureTagRequests.Load())
}

// TestVerifyPrefersBundles verifies that the legacy signatures are ignored
// once an artifact has a signature bundle, and that attestations are no
// signatures.
func TestVerifyPrefersBundles(t *testing.T) {
	t.Parallel()

	host := testRegistry(t, true)
	sigstore := newTestSigstore(t)
	sut := New(logr.Discard())

	pull := func(name, keyRef string) error {
		_, err := sut.Pull(t.Context(), host+"/"+name+":v1", "", "", nil, &PullOptions{
			PlainHTTP: true, TrustedRootPath: sigstore.trustedRootPath, KeyRef: keyRef,
		})

		return err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	publicKey := writePublicKey(t, key.Public())

	t.Run("invalid bundle next to valid legacy signature", func(t *testing.T) {
		t.Parallel()

		subject := pushUnsigned(t, sut, host, "prefer")
		repo := testRepository(t, host, "prefer")

		signedPayload := legacyPayload(t, host+"/prefer", subject.Digest)
		attachLegacySignatures(
			t,
			repo,
			subject.Digest,
			signedPayload,
			sigstore.keyLegacySignature(t, signedPayload, key),
		)
		require.NoError(t, pull("prefer", publicKey))

		// A bundle of another key replaces the legacy signature.
		bundle, _ := sigstore.keyBundle(t, subject.Digest, cosignSignPredicateType)
		require.NoError(t, sut.attachSignatureBundle(t.Context(), repo, &subject, bundle))
		require.ErrorContains(t, pull("prefer", publicKey), "verify signature")
	})

	t.Run("attestation with signature annotation", func(t *testing.T) {
		t.Parallel()

		subject := pushUnsigned(t, sut, host, "attestation")
		bundle, publicKeyPath := sigstore.keyBundle(
			t,
			subject.Digest,
			"https://slsa.dev/provenance/v1",
		)
		require.NoError(t, sut.attachSignatureBundle(
			t.Context(), testRepository(t, host, "attestation"), &subject, bundle,
		))

		err := pull("attestation", publicKeyPath)
		require.ErrorIs(t, err, ErrInvalidSignatureBundle)
		require.ErrorContains(t, err, "predicate type")
	})

	t.Run("attestation", func(t *testing.T) {
		t.Parallel()

		subject := pushUnsigned(t, sut, host, "provenance")
		repo := testRepository(t, host, "provenance")
		bundle, publicKeyPath := sigstore.keyBundle(
			t,
			subject.Digest,
			"https://slsa.dev/provenance/v1",
		)
		layer := orascontent.NewDescriptorFromBytes(bundleMediaType, bundle)
		require.NoError(t, repo.Push(t.Context(), layer, bytes.NewReader(bundle)))

		_, err := oras.PackManifest(t.Context(), repo, oras.PackManifestVersion1_1, bundleMediaType,
			oras.PackManifestOptions{
				Subject: &subject,
				Layers:  []ocispec.Descriptor{layer},
				ManifestAnnotations: map[string]string{
					annotationBundlePredicateType: "https://slsa.dev/provenance/v1",
				},
			},
		)
		require.NoError(t, err)

		require.ErrorIs(t, pull("provenance", publicKeyPath), ErrNoSignature)
	})
}

func TestVerifierConfig(t *testing.T) {
	t.Parallel()

	sigstore := newTestSigstore(t)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	entity := func(t *testing.T, integratedTimes ...int64) *testSignedEntity {
		t.Helper()

		entries := make([]*protorekor.TransparencyLogEntry, 0, len(integratedTimes))

		for _, integratedTime := range integratedTimes {
			annotations := sigstore.keyLegacySignature(t, []byte("payload"), key)

			entry, err := legacyTlogEntry([]byte(annotations[annotationLegacyBundle]))
			require.NoError(t, err)

			entry.IntegratedTime = integratedTime
			entries = append(entries, entry)
		}

		return &testSignedEntity{entries: entries}
	}

	for _, tc := range []struct {
		name     string
		material root.TrustedMaterial
		entries  []int64
		keyed    bool
		expected verifierConfig
	}{
		{
			name:     "keyless with certificate transparency log",
			material: sigstore.vs,
			entries:  []int64{1},
			expected: verifierConfig{signedCertificateTimestamps: true},
		},
		{
			name:     "keyless without certificate transparency log",
			material: sigstore.trustedRoot,
			entries:  []int64{1},
		},
		{
			name:     "keyless with Rekor v2 entry",
			material: sigstore.vs,
			entries:  []int64{0},
			expected: verifierConfig{signedCertificateTimestamps: true, signedTimestamps: true},
		},
		{
			name:     "keyless with Rekor v1 and v2 entries",
			material: sigstore.vs,
			entries:  []int64{0, 1},
			expected: verifierConfig{signedCertificateTimestamps: true},
		},
		{
			name:     "key",
			material: sigstore.vs,
			entries:  []int64{0},
			keyed:    true,
			expected: verifierConfig{keyed: true},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			config, err := newVerifierConfig(entity(t, tc.entries...), tc.material, tc.keyed)
			require.NoError(t, err)
			require.Equal(t, tc.expected, config)
			require.NotEmpty(t, config.options())
		})
	}
}

// testSignedEntity only has transparency log entries.
type testSignedEntity struct {
	verify.BaseSignedEntity

	entries []*protorekor.TransparencyLogEntry
}

func (e *testSignedEntity) TlogEntries() ([]*tlog.Entry, error) {
	entries := make([]*tlog.Entry, 0, len(e.entries))

	for _, entry := range e.entries {
		parsed, err := tlog.NewTlogEntry(entry)
		if err != nil {
			return nil, err
		}

		entries = append(entries, parsed)
	}

	return entries, nil
}

func TestBundleOptions(t *testing.T) {
	t.Parallel()

	service := func(url string, version uint32) []root.Service {
		return []root.Service{
			{URL: url, MajorAPIVersion: version, ValidityPeriodStart: time.Now().Add(-time.Hour)},
		}
	}
	any1 := root.ServiceConfiguration{Selector: prototrustroot.ServiceSelector_ANY, Count: 1}

	config := func(t *testing.T, rekorVersion uint32, tsa bool) *root.SigningConfig {
		t.Helper()

		var authorities []root.Service
		if tsa {
			authorities = service("https://tsa.example.com", 1)
		}

		signingConfig, err := root.NewSigningConfig(
			root.SigningConfigMediaType02,
			service("https://fulcio.example.com", 1),
			service("https://oauth2.example.com", 1),
			service("https://rekor.example.com", rekorVersion),
			any1, authorities, any1,
		)
		require.NoError(t, err)

		return signingConfig
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
	require.ErrorIs(t, err, ErrRekorV2WithoutTimestampAuthority)
}

func TestSignatureStatement(t *testing.T) {
	t.Parallel()

	subject := digest.FromString("artifact")

	statement, err := signatureStatement(subject)
	require.NoError(t, err)

	var decoded struct {
		Type          string `json:"_type"` //nolint:tagliatelle // in-toto field name
		PredicateType string `json:"predicateType"`
		Subject       []struct {
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
	}
	require.NoError(t, json.Unmarshal(statement, &decoded))
	require.Equal(t, "https://in-toto.io/Statement/v1", decoded.Type)
	require.Equal(t, cosignSignPredicateType, decoded.PredicateType)
	require.Len(t, decoded.Subject, 1)
	require.Equal(t, map[string]string{"sha256": subject.Encoded()}, decoded.Subject[0].Digest)

	_, err = signatureStatement("invalid")
	require.Error(t, err)
}

func TestWithPublicKey(t *testing.T) {
	t.Parallel()

	sut := New(logr.Discard())

	for _, keyRef := range []string{"k8s://namespace/secret", "awskms:///alias/key", "https://example.com/key.pub"} {
		_, err := sut.withPublicKey(&root.BaseTrustedMaterial{}, keyRef)
		require.ErrorIs(t, err, ErrUnsupportedKeyRef, keyRef)
	}

	_, err := sut.withPublicKey(
		&root.BaseTrustedMaterial{},
		filepath.Join(t.TempDir(), "missing.pub"),
	)
	require.ErrorIs(t, err, os.ErrNotExist)

	notAKey := filepath.Join(t.TempDir(), "cosign.pub")
	require.NoError(t, os.WriteFile(notAKey, []byte("not a key"), 0o600))

	_, err = sut.withPublicKey(&root.BaseTrustedMaterial{}, notAKey)
	require.ErrorContains(t, err, "decode public key")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	material, err := sut.withPublicKey(&root.BaseTrustedMaterial{}, writePublicKey(t, key.Public()))
	require.NoError(t, err)

	verifier, err := material.PublicKeyVerifier("any hint")
	require.NoError(t, err)

	publicKey, err := verifier.PublicKey()
	require.NoError(t, err)
	require.True(t, key.PublicKey.Equal(publicKey))
}

func TestLegacyBundle(t *testing.T) {
	t.Parallel()

	signedPayload := []byte("payload")
	signatureAnnotation := base64.StdEncoding.EncodeToString([]byte("signature"))

	for _, tc := range []struct {
		name        string
		annotations map[string]string
		wantErr     bool
	}{
		{name: "key signature", annotations: map[string]string{annotationLegacySignature: signatureAnnotation}},
		{name: "no signature", annotations: map[string]string{}, wantErr: true},
		{name: "invalid signature", annotations: map[string]string{annotationLegacySignature: "%"}, wantErr: true},
		{
			name: "invalid certificate",
			annotations: map[string]string{
				annotationLegacySignature: signatureAnnotation, annotationLegacyCertificate: "not a certificate",
			},
			wantErr: true,
		},
		{
			name: "invalid transparency log bundle",
			annotations: map[string]string{
				annotationLegacySignature: signatureAnnotation, annotationLegacyBundle: "{",
			},
			wantErr: true,
		},
		{
			name: "invalid transparency log entry",
			annotations: map[string]string{
				annotationLegacySignature: signatureAnnotation,
				annotationLegacyBundle:    `{"Payload":{"body":"e30=","logID":"00"}}`,
			},
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			bundle, err := legacyBundle(tc.annotations, signedPayload)
			if tc.wantErr {
				require.ErrorIs(t, err, ErrInvalidSignatureBundle)

				return
			}

			require.NoError(t, err)

			content, err := bundle.SignatureContent()
			require.NoError(t, err)
			require.Equal(t, []byte("signature"), content.Signature())

			sum := sha256.Sum256(signedPayload)
			require.Equal(t, sum[:], content.MessageSignatureContent().Digest())
		})
	}
}

func TestCheckLegacyClaims(t *testing.T) {
	t.Parallel()

	subject := digest.FromString("artifact")

	require.NoError(
		t,
		checkLegacyClaims(legacyPayload(t, "registry.example.com/profile", subject), subject),
	)
	require.ErrorIs(t, checkLegacyClaims(
		legacyPayload(t, "registry.example.com/profile", digest.FromString("other")), subject,
	), ErrSignatureDigestMismatch)
	require.Error(t, checkLegacyClaims([]byte("{"), subject))
}
