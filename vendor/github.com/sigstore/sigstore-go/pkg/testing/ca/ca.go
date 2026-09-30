// Copyright 2023 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/digitorus/timestamp"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/swag/conv"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	rekortilespb "github.com/sigstore/rekor-tiles/v2/pkg/generated/protobuf"
	rekornote "github.com/sigstore/rekor-tiles/v2/pkg/note"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/pki"
	"github.com/sigstore/rekor/pkg/types"
	dsseEntry "github.com/sigstore/rekor/pkg/types/dsse"
	"github.com/sigstore/rekor/pkg/types/hashedrekord"
	"github.com/sigstore/rekor/pkg/types/intoto"
	"github.com/sigstore/rekor/pkg/types/rekord"
	"github.com/sigstore/rekor/pkg/util"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tlog"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	sigdsse "github.com/sigstore/sigstore/pkg/signature/dsse"
	tsx509 "github.com/sigstore/timestamp-authority/v2/pkg/x509"
	f_log "github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/merkle/rfc6962"
	"golang.org/x/mod/sumdb/note"
	"google.golang.org/protobuf/encoding/protojson"
)

type VirtualSigstore struct {
	fulcioCA                *root.FulcioCertificateAuthority
	fulcioIntermediateKey   *ecdsa.PrivateKey
	tsaCA                   *root.SigstoreTimestampingAuthority
	tsaLeafKey              *ecdsa.PrivateKey
	rekorKey                *ecdsa.PrivateKey
	rekorRoot               []byte
	ctlogKey                *ecdsa.PrivateKey
	publicKeyVerifier       map[string]root.TimeConstrainedVerifier
	signingAlgorithmDetails signature.AlgorithmDetails
}

func NewVirtualSigstoreWithSigningAlg(signingKeyDetails v1.PublicKeyDetails) (*VirtualSigstore, error) {
	ss := &VirtualSigstore{
		fulcioCA: &root.FulcioCertificateAuthority{URI: "https://virtual.fulcio.sigstore.dev"},
		tsaCA:    &root.SigstoreTimestampingAuthority{URI: "https://virtual.tsa.sigstore.dev"},
	}

	rootCert, rootKey, err := GenerateRootCa()
	if err != nil {
		return nil, err
	}
	ss.fulcioCA.Root = rootCert
	ss.tsaCA.Root = rootCert

	intermediateCert, intermediateKey, _ := GenerateFulcioIntermediate(rootCert, rootKey)
	ss.fulcioCA.Intermediates = []*x509.Certificate{intermediateCert}
	ss.fulcioIntermediateKey = intermediateKey

	tsaIntermediateCert, tsaIntermediateKey, err := GenerateTSAIntermediate(rootCert, rootKey)
	if err != nil {
		return nil, err
	}
	ss.tsaCA.Intermediates = []*x509.Certificate{tsaIntermediateCert}
	tsaLeafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tsaLeafCert, err := GenerateTSALeafCert(time.Now().Add(-5*time.Minute), tsaLeafKey, tsaIntermediateCert, tsaIntermediateKey)
	if err != nil {
		return nil, err
	}
	ss.tsaCA.Leaf = tsaLeafCert
	ss.tsaLeafKey = tsaLeafKey

	ss.fulcioCA.ValidityPeriodStart = time.Now().Add(-5 * time.Hour)
	ss.fulcioCA.ValidityPeriodEnd = time.Now().Add(time.Hour)
	ss.tsaCA.ValidityPeriodStart = time.Now().Add(-5 * time.Hour)
	ss.tsaCA.ValidityPeriodEnd = time.Now().Add(time.Hour)

	ss.rekorKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	ss.ctlogKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	ss.signingAlgorithmDetails, err = signature.GetAlgorithmDetails(signingKeyDetails)
	if err != nil {
		return nil, err
	}

	return ss, nil
}

func NewVirtualSigstore() (*VirtualSigstore, error) {
	return NewVirtualSigstoreWithSigningAlg(v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256)
}

func NewVirtualSigstoreWithExistingRekorEntry() (*VirtualSigstore, error) {
	vs, err := NewVirtualSigstore()
	if err != nil {
		return nil, err
	}
	entry := []byte("foo")
	hash := sha256.Sum256(append([]byte("\000"), entry...))
	vs.rekorRoot = hash[:]
	return vs, nil
}

// getLogID calculates the digest of a PKIX-encoded public key
func getLogID(pub crypto.PublicKey) (string, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(pubBytes)
	return hex.EncodeToString(digest[:]), nil
}

func (ca *VirtualSigstore) RekorLogID() (string, error) {
	return getLogID(ca.rekorKey.Public())
}

func (ca *VirtualSigstore) RekorSignPayload(payload tlog.RekorPayload) ([]byte, error) {
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	canonicalized, err := jsoncanonicalizer.Transform(jsonPayload)
	if err != nil {
		return nil, err
	}
	signer, err := signature.LoadECDSASignerVerifier(ca.rekorKey, crypto.SHA256)
	if err != nil {
		return nil, err
	}
	bundleSig, err := signer.SignMessage(bytes.NewReader(canonicalized))
	if err != nil {
		return nil, err
	}
	return bundleSig, nil
}

func (ca *VirtualSigstore) GenerateLeafCert(identity, issuer string) (*x509.Certificate, crypto.PrivateKey, error) {
	var privKey crypto.PrivateKey
	var err error
	switch ca.signingAlgorithmDetails.GetKeyType() {
	case signature.ECDSA:
		var curve *elliptic.Curve
		curve, err = ca.signingAlgorithmDetails.GetECDSACurve()
		if err != nil {
			return nil, nil, err
		}
		privKey, err = ecdsa.GenerateKey(*curve, rand.Reader)
	case signature.RSA:
		var keySize signature.RSAKeySize
		keySize, err = ca.signingAlgorithmDetails.GetRSAKeySize()
		if err != nil {
			return nil, nil, err
		}
		privKey, err = rsa.GenerateKey(rand.Reader, int(keySize))
	case signature.ED25519:
		_, privKey, err = ed25519.GenerateKey(rand.Reader)
	}
	if err != nil {
		return nil, nil, err
	}
	leafCert, err := GenerateLeafCert(identity, issuer, time.Now(), privKey, ca.fulcioCA.Intermediates[0], ca.fulcioIntermediateKey)
	if err != nil {
		return nil, nil, err
	}
	return leafCert, privKey, nil
}

func (ca *VirtualSigstore) Attest(identity, issuer string, envelopeBody []byte) (*TestEntity, error) {
	// The timing here is important. We need to attest at a time when the leaf
	// certificate is valid, so we match what GenerateLeafCert() does, above
	return ca.AttestAtTime(identity, issuer, envelopeBody, time.Now().Add(5*time.Minute), false)
}

func (ca *VirtualSigstore) AttestAtTime(identity, issuer string, envelopeBody []byte, integratedTime time.Time, generateInclusionProof bool) (*TestEntity, error) {
	leafCert, leafPrivKey, err := ca.GenerateLeafCert(identity, issuer)
	if err != nil {
		return nil, err
	}

	signer, err := signature.LoadSignerFromAlgorithmDetails(leafPrivKey, ca.signingAlgorithmDetails)
	if err != nil {
		return nil, err
	}

	dsseSigner, err := dsse.NewEnvelopeSigner(&sigdsse.SignerAdapter{
		SignatureSigner: signer,
		Pub:             leafCert.PublicKey.(*ecdsa.PublicKey),
	})
	if err != nil {
		return nil, err
	}

	envelope, err := dsseSigner.SignPayload(context.Background(), "application/vnd.in-toto+json", envelopeBody)
	if err != nil {
		return nil, err
	}

	sig, err := base64.StdEncoding.DecodeString(envelope.Signatures[0].Sig)
	if err != nil {
		return nil, err
	}

	tsr, err := generateTimestampingResponse(sig, ca.tsaCA.Leaf, ca.tsaLeafKey)
	if err != nil {
		return nil, err
	}

	entry, err := ca.GenerateTlogEntry(leafCert, envelope, sig, integratedTime.Unix(), generateInclusionProof)
	if err != nil {
		return nil, err
	}

	return &TestEntity{
		certChain:   []*x509.Certificate{leafCert, ca.fulcioCA.Intermediates[0], ca.fulcioCA.Root},
		timestamps:  [][]byte{tsr},
		envelope:    envelope,
		tlogEntries: []*tlog.Entry{entry},
	}, nil
}

// AttestHashedRekordV2 produces an attestation TestEntity with a Rekor v2 hashedrekord tlog entry.
func (ca *VirtualSigstore) AttestHashedRekordV2(identity, issuer string, envelopeBody []byte) (*TestEntity, error) {
	return ca.AttestAtTimeHashedRekordV2(identity, issuer, envelopeBody, time.Now().Add(5*time.Minute))
}

func (ca *VirtualSigstore) AttestAtTimeHashedRekordV2(identity, issuer string, envelopeBody []byte, integratedTime time.Time) (*TestEntity, error) {
	leafCert, leafPrivKey, err := ca.GenerateLeafCert(identity, issuer)
	if err != nil {
		return nil, err
	}

	signer, err := signature.LoadSignerFromAlgorithmDetails(leafPrivKey, ca.signingAlgorithmDetails)
	if err != nil {
		return nil, err
	}

	dsseSigner, err := dsse.NewEnvelopeSigner(&sigdsse.SignerAdapter{
		SignatureSigner: signer,
		Pub:             leafCert.PublicKey,
	})
	if err != nil {
		return nil, err
	}

	envelope, err := dsseSigner.SignPayload(context.Background(), "application/vnd.in-toto+json", envelopeBody)
	if err != nil {
		return nil, err
	}

	sig, err := base64.StdEncoding.DecodeString(envelope.Signatures[0].Sig)
	if err != nil {
		return nil, err
	}

	tsr, err := generateTimestampingResponse(sig, ca.tsaCA.Leaf, ca.tsaLeafKey)
	if err != nil {
		return nil, err
	}

	tlogEntry, err := ca.generateTlogEntryHashedRekordV2(leafCert, envelope.PayloadType, envelopeBody, sig, integratedTime.Unix())
	if err != nil {
		return nil, err
	}

	return &TestEntity{
		certChain:   []*x509.Certificate{leafCert, ca.fulcioCA.Intermediates[0], ca.fulcioCA.Root},
		timestamps:  [][]byte{tsr},
		envelope:    envelope,
		tlogEntries: []*tlog.Entry{tlogEntry},
	}, nil
}

func (ca *VirtualSigstore) generateTlogEntryHashedRekordV2(leafCert *x509.Certificate, payloadType string, payload []byte, sig []byte, integratedTime int64) (*tlog.Entry, error) {
	hf := ca.signingAlgorithmDetails.GetHashType()
	hasher := hf.New()
	hasher.Write(dsse.PAE(payloadType, payload))
	digest := hasher.Sum(nil)

	entryPB := &rekortilespb.Entry{
		ApiVersion: "0.0.2",
		Kind:       "hashedrekord",
		Spec: &rekortilespb.Spec{
			Spec: &rekortilespb.Spec_HashedRekordV002{
				HashedRekordV002: &rekortilespb.HashedRekordLogEntryV002{
					Data: &v1.HashOutput{
						Algorithm: ca.signingAlgorithmDetails.GetProtoHashType(),
						Digest:    digest,
					},
					Signature: &rekortilespb.Signature{
						Content: sig,
						Verifier: &rekortilespb.Verifier{
							KeyDetails: ca.signingAlgorithmDetails.GetSignatureAlgorithm(),
							Verifier: &rekortilespb.Verifier_X509Certificate{
								X509Certificate: &v1.X509Certificate{
									RawBytes: leafCert.Raw,
								},
							},
						},
					},
				},
			},
		},
	}
	serialized, err := protojson.Marshal(entryPB)
	if err != nil {
		return nil, fmt.Errorf("marshaling rekor v2 entry: %w", err)
	}
	// Canonicalize to match the server-side pipeline.
	body, err := jsoncanonicalizer.Transform(serialized)
	if err != nil {
		return nil, fmt.Errorf("canonicalizing rekor v2 entry: %w", err)
	}

	leafHash := rfc6962.DefaultHasher.HashLeaf(body)
	rekorLogs := ca.RekorLogs()
	rekorLogID, err := getLogID(ca.rekorKey.Public())
	if err != nil {
		return nil, err
	}
	rekorLog, ok := rekorLogs[rekorLogID]
	if !ok {
		return nil, fmt.Errorf("rekor log %s not found", rekorLogID)
	}
	u, err := url.Parse(rekorLog.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("parsing rekor BaseURL: %w", err)
	}
	origin := u.Hostname()

	sv, err := signature.LoadECDSASignerVerifier(ca.rekorKey, crypto.SHA256)
	if err != nil {
		return nil, err
	}
	noteSigner, err := rekornote.NewNoteSigner(context.Background(), origin, sv)
	if err != nil {
		return nil, err
	}
	cpRaw := f_log.Checkpoint{
		Origin: origin,
		Size:   1,
		Hash:   leafHash,
	}.Marshal()
	signedNote, err := note.Sign(&note.Note{Text: string(cpRaw)}, noteSigner)
	if err != nil {
		return nil, fmt.Errorf("signing checkpoint: %w", err)
	}

	rekorLogIDRaw, err := hex.DecodeString(rekorLogID)
	if err != nil {
		return nil, err
	}

	tle := &protorekor.TransparencyLogEntry{
		LogIndex:       0,
		LogId:          &v1.LogId{KeyId: rekorLogIDRaw},
		KindVersion:    &protorekor.KindVersion{Kind: "hashedrekord", Version: "0.0.2"},
		IntegratedTime: integratedTime,
		InclusionProof: &protorekor.InclusionProof{
			LogIndex:   0,
			TreeSize:   1,
			RootHash:   leafHash,
			Hashes:     [][]byte{},
			Checkpoint: &protorekor.Checkpoint{Envelope: string(signedNote)},
		},
		CanonicalizedBody: body,
	}

	return tlog.NewTlogEntry(tle)
}

func (ca *VirtualSigstore) Sign(identity, issuer string, artifact []byte) (*TestEntity, error) {
	return ca.SignAtTimeWithVersion(identity, issuer, artifact, time.Now().Add(5*time.Minute), "v0.3")
}

func (ca *VirtualSigstore) SignWithVersion(identity, issuer string, artifact []byte, version string) (*TestEntity, error) {
	return ca.SignAtTimeWithVersion(identity, issuer, artifact, time.Now().Add(5*time.Minute), version)
}

func (ca *VirtualSigstore) SignAtTime(identity, issuer string, artifact []byte, integratedTime time.Time) (*TestEntity, error) {
	return ca.SignAtTimeWithVersion(identity, issuer, artifact, integratedTime, "v0.3")
}

func (ca *VirtualSigstore) SignAtTimeWithVersion(identity, issuer string, artifact []byte, integratedTime time.Time, version string) (*TestEntity, error) {
	leafCert, leafPrivKey, err := ca.GenerateLeafCert(identity, issuer)
	if err != nil {
		return nil, err
	}

	signer, err := signature.LoadSignerFromAlgorithmDetails(leafPrivKey, ca.signingAlgorithmDetails)
	if err != nil {
		return nil, err
	}

	hashType := ca.signingAlgorithmDetails.GetHashType()
	hasher := hashType.New()
	hasher.Write(artifact)
	digest := hasher.Sum(nil)

	var digestString string
	switch hashType {
	case crypto.SHA256:
		digestString = "SHA2_256"
	case crypto.SHA384:
		digestString = "SHA2_384"
	case crypto.SHA512:
		digestString = "SHA2_512"
	}
	sig, err := signer.SignMessage(bytes.NewReader(artifact))
	if err != nil {
		return nil, err
	}

	tsr, err := generateTimestampingResponse(sig, ca.tsaCA.Leaf, ca.tsaLeafKey)
	if err != nil {
		return nil, err
	}

	entry, err := ca.generateTlogEntryHashedRekord(leafCert, artifact, sig, integratedTime.Unix())
	if err != nil {
		return nil, err
	}

	return &TestEntity{
		certChain:        []*x509.Certificate{leafCert, ca.fulcioCA.Intermediates[0], ca.fulcioCA.Root},
		timestamps:       [][]byte{tsr},
		messageSignature: bundle.NewMessageSignature(digest, digestString, sig),
		tlogEntries:      []*tlog.Entry{entry},
		version:          version,
	}, nil
}

func (ca *VirtualSigstore) GenerateTlogEntry(leafCert *x509.Certificate, envelope *dsse.Envelope, sig []byte, integratedTime int64, generateInclusionProof bool) (*tlog.Entry, error) {
	leafCertPem, err := cryptoutils.MarshalCertificateToPEM(leafCert)
	if err != nil {
		return nil, err
	}

	envelopeBytes, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	rekorBody, err := generateRekorEntry(dsseEntry.KIND, dsseEntry.New().DefaultVersion(), envelopeBytes, leafCertPem, sig, ca.signingAlgorithmDetails)
	if err != nil {
		return nil, err
	}

	rekorLogID, err := getLogID(ca.rekorKey.Public())
	if err != nil {
		return nil, err
	}

	rekorLogIDRaw, err := hex.DecodeString(rekorLogID)
	if err != nil {
		return nil, err
	}

	logIndex := int64(0)

	b := createRekorBundle(rekorLogID, integratedTime, logIndex, rekorBody)
	set, err := ca.RekorSignPayload(*b)
	if err != nil {
		return nil, err
	}

	rekorBodyRaw, err := base64.StdEncoding.DecodeString(rekorBody)
	if err != nil {
		return nil, err
	}

	var inclusionProof *models.InclusionProof
	if generateInclusionProof {
		inclusionProof, err = ca.GetInclusionProof(rekorBodyRaw)
		if err != nil {
			return nil, err
		}
	}
	return tlog.NewEntry(rekorBodyRaw, integratedTime, logIndex, rekorLogIDRaw, set, inclusionProof) //nolint:staticcheck
}

func (ca *VirtualSigstore) GetInclusionProof(rekorBodyRaw []byte) (*models.InclusionProof, error) {
	signer, err := signature.LoadECDSASignerVerifier(ca.rekorKey, crypto.SHA256)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(append([]byte("\000"), rekorBodyRaw...))
	rootHash := hash
	var pathHash []byte
	if ca.rekorRoot != nil {
		rootHash = sha256.Sum256(append([]byte("\001"), append(hash[:], ca.rekorRoot...)...))
		pathHash = ca.rekorRoot
	}
	encodedRootHash := hex.EncodeToString(rootHash[:])
	var pathHashes []string
	if pathHash != nil {
		pathHashes = make([]string, 1)
		pathHashes[0] = hex.EncodeToString(pathHash)
	}
	scBytes, err := util.CreateAndSignCheckpoint(context.Background(), "rekor.localhost", int64(123), uint64(42), rootHash[:], signer)
	if err != nil {
		return nil, err
	}

	return &models.InclusionProof{
		TreeSize:   conv.Pointer(int64(len(pathHashes) + 1)),
		RootHash:   &encodedRootHash,
		LogIndex:   conv.Pointer(int64(len(pathHashes))),
		Hashes:     pathHashes,
		Checkpoint: conv.Pointer(string(scBytes)),
	}, nil
}

func (ca *VirtualSigstore) generateTlogEntryHashedRekord(leafCert *x509.Certificate, artifact []byte, sig []byte, integratedTime int64) (*tlog.Entry, error) {
	leafCertPem, err := cryptoutils.MarshalCertificateToPEM(leafCert)
	if err != nil {
		return nil, err
	}

	rekorBody, err := generateRekorEntry(hashedrekord.KIND, hashedrekord.New().DefaultVersion(), artifact, leafCertPem, sig, ca.signingAlgorithmDetails)
	if err != nil {
		return nil, err
	}

	rekorLogID, err := getLogID(ca.rekorKey.Public())
	if err != nil {
		return nil, err
	}

	rekorLogIDRaw, err := hex.DecodeString(rekorLogID)
	if err != nil {
		return nil, err
	}

	logIndex := int64(1000)

	b := createRekorBundle(rekorLogID, integratedTime, logIndex, rekorBody)
	set, err := ca.RekorSignPayload(*b)
	if err != nil {
		return nil, err
	}

	rekorBodyRaw, err := base64.StdEncoding.DecodeString(rekorBody)
	if err != nil {
		return nil, err
	}

	return tlog.NewEntry(rekorBodyRaw, integratedTime, logIndex, rekorLogIDRaw, set, nil) //nolint:staticcheck
}

func (ca *VirtualSigstore) PublicKeyVerifier(keyID string) (root.TimeConstrainedVerifier, error) {
	v, ok := ca.publicKeyVerifier[keyID]
	if !ok {
		return nil, fmt.Errorf("public key not found for keyID: %s", keyID)
	}
	return v, nil
}

func generateRekorEntry(kind, version string, artifact []byte, cert []byte, sig []byte, algorithmDetails signature.AlgorithmDetails) (string, error) {
	// Generate the Rekor Entry
	entryImpl, err := createEntry(context.Background(), kind, version, artifact, cert, sig, algorithmDetails)
	if err != nil {
		return "", err
	}
	entryBytes, err := entryImpl.Canonicalize(context.Background())
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(entryBytes), nil
}

func createEntry(ctx context.Context, kind, apiVersion string, blobBytes, certBytes, sigBytes []byte, algorithmDetails signature.AlgorithmDetails) (types.EntryImpl, error) {
	props := types.ArtifactProperties{
		PublicKeyBytes: [][]byte{certBytes},
		PKIFormat:      string(pki.X509),
	}
	switch kind {
	case rekord.KIND, intoto.KIND, dsseEntry.KIND:
		props.ArtifactBytes = blobBytes
		props.SignatureBytes = sigBytes
	case hashedrekord.KIND:
		hashType := algorithmDetails.GetHashType()
		hasher := hashType.New()
		hasher.Write(blobBytes)
		blobHash := hasher.Sum(nil)

		props.ArtifactHash = strings.ToLower(hex.EncodeToString(blobHash))
		props.SignatureBytes = sigBytes
	default:
		return nil, fmt.Errorf("unexpected entry kind: %s", kind)
	}
	proposedEntry, err := types.NewProposedEntry(ctx, kind, apiVersion, props)
	if err != nil {
		return nil, err
	}
	eimpl, err := types.CreateVersionedEntry(proposedEntry)
	if err != nil {
		return nil, err
	}

	can, err := types.CanonicalizeEntry(ctx, eimpl)
	if err != nil {
		return nil, err
	}
	proposedEntryCan, err := models.UnmarshalProposedEntry(bytes.NewReader(can), runtime.JSONConsumer())
	if err != nil {
		return nil, err
	}

	return types.UnmarshalEntry(proposedEntryCan)
}

func createRekorBundle(logID string, integratedTime int64, logIndex int64, rekorEntry string) *tlog.RekorPayload {
	return &tlog.RekorPayload{
		LogID:          logID,
		IntegratedTime: integratedTime,
		LogIndex:       logIndex,
		Body:           rekorEntry,
	}
}

func (ca *VirtualSigstore) TimestampResponse(sig []byte) ([]byte, error) {
	return generateTimestampingResponse(sig, ca.tsaCA.Leaf, ca.tsaLeafKey)
}

func generateTimestampingResponse(sig []byte, tsaCert *x509.Certificate, tsaKey *ecdsa.PrivateKey) ([]byte, error) {
	var hash crypto.Hash
	switch tsaKey.Curve {
	case elliptic.P256():
		hash = crypto.SHA256
	case elliptic.P384():
		hash = crypto.SHA384
	case elliptic.P521():
		hash = crypto.SHA512
	}
	tsq, err := timestamp.CreateRequest(bytes.NewReader(sig), &timestamp.RequestOptions{
		Hash: hash,
	})
	if err != nil {
		return nil, err
	}

	req, err := timestamp.ParseRequest([]byte(tsq))
	if err != nil {
		return nil, err
	}

	tsTemplate := timestamp.Timestamp{
		HashAlgorithm:   req.HashAlgorithm,
		HashedMessage:   req.HashedMessage,
		Time:            time.Now(),
		Policy:          asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 2},
		Ordering:        false,
		Qualified:       false,
		ExtraExtensions: req.Extensions,
	}

	return tsTemplate.CreateResponseWithOpts(tsaCert, tsaKey, hash)
}

func (ca *VirtualSigstore) TimestampingAuthorities() []root.TimestampingAuthority {
	return []root.TimestampingAuthority{ca.tsaCA}
}

func (ca *VirtualSigstore) FulcioCertificateAuthorities() []root.CertificateAuthority {
	return []root.CertificateAuthority{ca.fulcioCA}
}

func (ca *VirtualSigstore) RekorLogs() map[string]*root.TransparencyLog {
	verifiers := make(map[string]*root.TransparencyLog)
	logID, err := getLogID(ca.rekorKey.Public())
	if err != nil {
		panic(err)
	}
	verifiers[logID] = &root.TransparencyLog{
		// BaseURL must parse to a non-empty hostname for Rekor v2 verification,
		// since the checkpoint origin is derived from url.Parse(BaseURL).Hostname().
		// The hostname matches what GetInclusionProof signs for v1 checkpoints.
		BaseURL:             "https://rekor.localhost",
		ID:                  []byte(logID),
		ValidityPeriodStart: time.Now().Add(-time.Hour),
		ValidityPeriodEnd:   time.Now().Add(time.Hour),
		HashFunc:            crypto.SHA256,
		PublicKey:           ca.rekorKey.Public(),
		SignatureHashFunc:   crypto.SHA256,
	}
	return verifiers
}

func (ca *VirtualSigstore) CTLogs() map[string]*root.TransparencyLog {
	verifiers := make(map[string]*root.TransparencyLog)
	logID, err := getLogID(ca.ctlogKey.Public())
	if err != nil {
		panic(err)
	}
	verifiers[logID] = &root.TransparencyLog{
		BaseURL:             "test",
		ID:                  []byte(logID),
		ValidityPeriodStart: time.Now().Add(-time.Hour),
		ValidityPeriodEnd:   time.Now().Add(time.Hour),
		HashFunc:            crypto.SHA256,
		PublicKey:           ca.ctlogKey.Public(),
	}
	return verifiers
}

type TestEntity struct {
	certChain        []*x509.Certificate
	envelope         *dsse.Envelope
	messageSignature *bundle.MessageSignature
	timestamps       [][]byte
	tlogEntries      []*tlog.Entry
	version          string
}

func (e *TestEntity) VerificationContent() (verify.VerificationContent, error) {
	return bundle.NewCertificate(e.certChain[0]), nil
}

func (e *TestEntity) HasInclusionPromise() bool {
	return true
}

func (e *TestEntity) Version() (string, error) {
	return e.version, nil
}

func (e *TestEntity) HasInclusionProof() bool {
	for _, tlog := range e.tlogEntries {
		if tlog.HasInclusionProof() {
			return true
		}
	}
	return false
}

func (e *TestEntity) SignatureContent() (verify.SignatureContent, error) {
	if e.envelope != nil {
		return &bundle.Envelope{Envelope: e.envelope}, nil
	}
	return e.messageSignature, nil
}

func (e *TestEntity) Timestamps() ([][]byte, error) {
	return e.timestamps, nil
}

func (e *TestEntity) TlogEntries() ([]*tlog.Entry, error) {
	return e.tlogEntries, nil
}

// Much of the following code is adapted from cosign/test/cert_utils.go

func createCertificate(template *x509.Certificate, parent *x509.Certificate, pub any, priv crypto.Signer) (*x509.Certificate, error) {
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func GenerateRootCa() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "sigstore",
			Organization: []string{"sigstore.dev"},
		},
		NotBefore:             time.Now().Add(-5 * time.Hour),
		NotAfter:              time.Now().Add(5 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	cert, err := createCertificate(rootTemplate, rootTemplate, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	return cert, priv, nil
}

func GenerateFulcioIntermediate(rootTemplate *x509.Certificate, rootPriv crypto.Signer) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	subTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "sigstore-intermediate",
			Organization: []string{"sigstore.dev"},
		},
		NotBefore:             time.Now().Add(-2 * time.Minute),
		NotAfter:              time.Now().Add(2 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	cert, err := createCertificate(subTemplate, rootTemplate, &priv.PublicKey, rootPriv)
	if err != nil {
		return nil, nil, err
	}

	return cert, priv, nil
}

func GenerateTSAIntermediate(rootTemplate *x509.Certificate, rootPriv crypto.Signer) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	subTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "sigstore-tsa-intermediate",
			Organization: []string{"sigstore.dev"},
		},
		NotBefore:             time.Now().Add(-2 * time.Minute),
		NotAfter:              time.Now().Add(2 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	cert, err := createCertificate(subTemplate, rootTemplate, &priv.PublicKey, rootPriv)
	if err != nil {
		return nil, nil, err
	}

	return cert, priv, nil
}

func GenerateLeafCert(subject string, oidcIssuer string, expiration time.Time, priv crypto.PrivateKey,
	parentTemplate *x509.Certificate, parentPriv crypto.Signer) (*x509.Certificate, error) {
	certTemplate := &x509.Certificate{
		SerialNumber:   big.NewInt(1),
		EmailAddresses: []string{subject},
		NotBefore:      expiration,
		NotAfter:       expiration.Add(10 * time.Minute),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		IsCA:           false,
		ExtraExtensions: []pkix.Extension{{
			// OID for OIDC Issuer extension
			Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1},
			Critical: false,
			Value:    []byte(oidcIssuer),
		},
		},
	}

	signer, ok := priv.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key does not implement crypto.Signer")
	}

	cert, err := createCertificate(certTemplate, parentTemplate, signer.Public(), parentPriv)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func GenerateTSALeafCert(expiration time.Time, priv *ecdsa.PrivateKey, parentTemplate *x509.Certificate, parentPriv crypto.Signer) (*x509.Certificate, error) {
	timestampExt, err := asn1.Marshal([]asn1.ObjectIdentifier{tsx509.EKUTimestampingOID})
	if err != nil {
		return nil, err
	}

	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    expiration,
		NotAfter:     expiration.Add(10 * time.Minute),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		IsCA:         false,
		// set EKU to x509.ExtKeyUsageTimeStamping but with a critical bit
		ExtraExtensions: []pkix.Extension{
			{
				Id:       asn1.ObjectIdentifier{2, 5, 29, 37},
				Critical: true,
				Value:    timestampExt,
			},
		},
	}

	cert, err := createCertificate(certTemplate, parentTemplate, &priv.PublicKey, parentPriv)
	if err != nil {
		return nil, err
	}

	return cert, nil
}
