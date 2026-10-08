# Verifying the released artifacts

<!-- toc -->
- [What a release provides](#what-a-release-provides)
- [Where the signatures and attestations are](#where-the-signatures-and-attestations-are)
- [SLSA build levels](#slsa-build-levels)
- [Container image](#container-image)
- [GitHub provenance of the container images](#github-provenance-of-the-container-images)
- [Verification summaries](#verification-summaries)
  - [What a summary says](#what-a-summary-says)
  - [Verify a summary](#verify-a-summary)
  - [Levels](#levels)
  - [Missing and failed summaries](#missing-and-failed-summaries)
- [Enforcing the verification in a cluster](#enforcing-the-verification-in-a-cluster)
- [Command line binaries](#command-line-binaries)
- [Software bill of materials](#software-bill-of-materials)
- [Helm chart](#helm-chart)
- [OCI artifacts on <code>registry.k8s.io</code>](#oci-artifacts-on-registryk8sio)
- [Security profiles](#security-profiles)
- [Staging images](#staging-images)
- [Older releases](#older-releases)
<!-- /toc -->

Every artifact of a release is signed with [Sigstore][sigstore] keyless
signing and carries [SLSA][slsa] build provenance. This page collects the
verification commands for all of them, so a release only has to link here.

The commands need [cosign][cosign] v3 or later, because the signatures use the
Sigstore bundle format that cosign v2 cannot read. The provenance checks of the
release assets use the [GitHub CLI][gh], and the digest lookups
[crane][crane].

Every release links to this page at its own tag, so the page describes the
release it is read at. Set `VERSION` to that tag, the [release][releases] to
verify:

```console
> export VERSION=vx.y.z
```

On `main` the page follows the development of the next release and may
describe what no release has yet. To verify the latest release, read the page
at its tag, which this command sets:

```console
> export VERSION=$(gh release view -R kubernetes-sigs/security-profiles-operator --json tagName -q .tagName)
```

v1.1.0 and the releases before it were built in another way and provide less,
so not every command of this page works for them, see
[older releases](#older-releases).

## What a release provides

| Artifact | Signature | Provenance | SBOM |
| -------- | --------- | ---------- | ---- |
| Container images on `registry.k8s.io` | `krel-trust`, staging build | Build L3 from GitHub and Build L1 from Cloud Build, of the per-arch images | attested, of the per-arch images |
| Operator bundle and catalog on `registry.k8s.io` | `krel-trust`, staging build | Build L1 from Cloud Build | attested |
| `spoc` binaries | release workflow | Build L3 from GitHub | `spoc.spdx.json`, `spoc-native.spdx.json` |
| `spoc.spdx.json`, `spoc-native.spdx.json` | release workflow | Build L3 from GitHub | |
| Helm chart archive on the release page | release workflow | Build L3 from GitHub | |
| Helm chart on `registry.k8s.io` | `krel-trust`, staging build | Build L3 from GitHub | attested |
| `spoc` on `registry.k8s.io` | `krel-trust`, staging build | Build L3 from GitHub | attested, the ones of the release page |
| Security profiles on `registry.k8s.io` | `krel-trust`, staging build | Build L1 from Cloud Build | attested |

On `registry.k8s.io` the image promoter signs as `krel-trust` and carries the
signature of the staging build along with the attestations.
[SLSA build levels](#slsa-build-levels) explains the levels. Every digest
the image promoter promotes also gets a
[verification summary](#verification-summaries) when it is promoted, which
says whether the attestations of the digest passed the policy of this project.

The security profiles are not part of a release. The base profiles are
published on their own, tagged with the version of the runtime they were
recorded against, see [security profiles](#security-profiles).

## Where the signatures and attestations are

The release assets on GitHub have their signatures (`*.sigstore.json`) and
their provenance (`*.intoto.jsonl`) next to them on the release page. The
provenance is in the GitHub attestation store as well.

Everything on `registry.k8s.io` gets there from the staging registry
`us-central1-docker.pkg.dev/k8s-staging-images/sp-operator` through the
[Kubernetes image promoter][promoter]:

1. The build signs what it pushes to staging and attaches the attestations as
   OCI referrers: SLSA provenance and SPDX SBOMs for the images, profiles and
   charts, and for the images also a vulnerability scan, an OpenVEX document,
   the build environment and the OpenSSF Scorecard result. `spoc` and the
   released chart get the GitHub provenance of the release and their SBOMs
   from the release artifacts job.
   [Staging attestations](release.md#staging-attestations) has the full list.
1. The promoter copies the artifacts by digest, so a promoted artifact is the
   one the build attested, and signs it as `krel-trust`.
1. The promoter verifies the staging attestations of every digest against the
   [provenance policy][promoter-policies] of this project and
   [carries][promoter-carry] the ones it accepts to `registry.k8s.io`: they
   are copied unchanged next to the promoted digest, in the repository the
   promoter manifest lists the digest in. For the container images these are
   the per-arch repositories, see [container image](#container-image).
1. The promoter writes a [verification summary](#verification-summaries) for
   the digest, next to its promotion record.

`cosign tree` lists the signatures and attestations of a digest, which shows
what a promoted artifact carries:

```console
> cosign tree registry.k8s.io/security-profiles-operator/security-profiles-operator-amd64:$VERSION
```

The staging registry deletes images 90 days after their push. Until then, the
attestations of a promoted digest can be verified in staging too, with the
same commands and the staging reference of the digest. That is the only place
for a digest that was promoted without its attestations, because it doesn't
satisfy the policy or was promoted before the promoter carried attestations,
see [older releases](#older-releases) and
[attestations on registry.k8s.io](release.md#attestations-on-registryk8sio).

## SLSA build levels

The `spoc` binaries, their SBOMs and the Helm chart archive on the release
page are built on GitHub Actions and meet [SLSA Build L3][slsa-l3], and so do
`spoc` and the Helm chart on `registry.k8s.io`, which are the same files in
OCI manifests built and attested by the same workflows, see
[OCI artifacts on `registry.k8s.io`](#oci-artifacts-on-registryk8sio). The build
jobs hold no signing identity and no write access. They only pass the digests
of their outputs to the isolated reusable
[`provenance`](../.github/workflows/provenance.yml) workflow, which generates and
signs the provenance as a [GitHub artifact attestation][attestations]. Separate
jobs that run no repository code sign the artifacts and attach them to the
release. The release builds take their nix dependencies only from
`cache.nixos.org` or build them, never from the project's Cachix cache, which
CI jobs running repository code can write to. Development builds of `main` may
use that cache, so only the provenance of releases makes the L3 claim.

The container images, the operator bundle and catalog, the security profiles
and the development charts of `main` are built on Cloud Build and meet SLSA
Build L1 only, apart from the per-arch images of releases, see below. Their
provenance is generated and signed by the build itself, with the same service
account as the build steps, so the build steps could forge it. Its
`runDetails.builder.id` therefore names the Cloud Build configuration and
service account of the staging project, not Google's build platform, and its
`buildType` points to the documentation of the built commit.
The build toolchain they compile with, `quay.io/security-profiles-operator/build`,
is built without caches on `main` and signed and attested by a job of the
[`build`](../.github/workflows/build.yml) workflow that runs no repository code.
The image builds only substitute from `cache.nixos.org`, whatever the build
image configures. Build images pinned in `Dockerfile` before that change were
still built with the old workflow, which used the GitHub Actions cache and
the Cachix cache, until `BUILD_IMAGE` is pinned to an image built by it.

The per-architecture images are reproducible, the same commit gives the same
image digests. [`hack/image-cross.sh`](../hack/image-cross.sh) builds them
with a pinned BuildKit image, sets `SOURCE_DATE_EPOCH` to the commit time and
clamps the file times in the layers to it. The
[`image-reproducible`](../.github/workflows/image-reproducible.yml) workflow
builds them again on GitHub Actions for every push to `main`, without pushing
anything, and fails if their digests differ from the staging images Cloud
Build pushed for the commit. This doesn't change the build level of the
provenance from Cloud Build, which lists the BuildKit image as a dependency
and stays at L1. For a release, the same workflow builds the per-arch images
of the tagged commit and has their digests attested like `spoc`, which gives
the per-arch images of a release SLSA Build L3 provenance as well, see
[GitHub provenance of the container images](#github-provenance-of-the-container-images).
Images of commits from before the BuildKit image was pinned are not
reproducible. To rebuild the images of a commit yourself and compare them
with its staging images, with docker and buildx on a `linux/amd64` machine,
like Cloud Build and GitHub Actions (the build image is only published for
it):

```console
> git checkout $COMMIT
> PUSH=false hack/image-cross.sh
> cat build/image-digests
> STAGING_WAIT=0 hack/ci/compare-staging-images.sh
```

## Container image

The images on `registry.k8s.io` are promoted by the Kubernetes image promoter,
which signs them as `krel-trust`:

```console
> cosign verify \
    --certificate-identity krel-trust@k8s-releng-prod.iam.gserviceaccount.com \
    --certificate-oidc-issuer https://accounts.google.com \
    registry.k8s.io/security-profiles-operator/security-profiles-operator:$VERSION
```

The same command works for the operator bundle, the catalog, the Helm chart
(`charts/security-profiles-operator:${VERSION#v}`), `spoc` and the promoted
`base/*` profiles by replacing the image name.

The build attests the per-architecture images, so their provenance, SBOMs,
vulnerability scan, VEX document, build environment and OpenSSF Scorecard
result are in the per-arch repositories, signed by the staging build, except
for v1.1.0 and [older releases](#older-releases). Verify them by predicate
type, here the provenance of the `amd64` image:

```console
> cosign verify-attestation \
    --type https://slsa.dev/provenance/v1 \
    --certificate-identity sp-operator-sa@k8s-staging-images.iam.gserviceaccount.com \
    --certificate-oidc-issuer https://accounts.google.com \
    registry.k8s.io/security-profiles-operator/security-profiles-operator-amd64:$VERSION
```

[Staging attestations](release.md#staging-attestations) lists the other
predicate types, and the operator bundle, the catalog and the profiles verify
in the same way in their own repositories. That provenance is SLSA Build L1,
the one of the next section is L3, see [SLSA build levels](#slsa-build-levels).

The platform images of the manifest list are the per-arch images, with the
same digests, so the attested image is the one a node pulls. The last two
commands print the same digest:

```console
> DIGEST=$(crane digest registry.k8s.io/security-profiles-operator/security-profiles-operator-amd64:$VERSION)
> echo $DIGEST
> crane digest --platform linux/amd64 \
    registry.k8s.io/security-profiles-operator/security-profiles-operator:$VERSION
```

The repository of the manifest list,
`registry.k8s.io/security-profiles-operator/security-profiles-operator`, holds
the signatures of the manifest list and what the promoter writes itself: its
signature of the platform manifests, its promotion record of the manifest
list and a [verification summary](#verification-summaries) for the manifest
list and for each platform manifest. The promoter doesn't copy the
attestations of the platform manifests there, because the promoter manifest
doesn't list their digests in that repository. The staging registry has them
in both places, so there `$DIGEST` also verifies as
`us-central1-docker.pkg.dev/k8s-staging-images/sp-operator/security-profiles-operator@$DIGEST`.

## GitHub provenance of the container images

A release attests its per-architecture images on GitHub too, v1.1.0 and
[older releases](#older-releases) don't. The
[`image-reproducible`](../.github/workflows/image-reproducible.yml) workflow
of the release builds them from the tagged commit, and the isolated
[`provenance`](../.github/workflows/provenance.yml) workflow attests their
digests with SLSA Build L3 provenance, the `images.intoto.jsonl` asset of the
release. The images are reproducible, so these are the digests Cloud Build
pushed to staging, which get promoted: the release artifacts job fails
otherwise, see [per-arch images](release.md#per-arch-images). Verify the
per-arch image of your architecture with the GitHub attestation store, or with
`--bundle images.intoto.jsonl` from the release page:

```console
> gh attestation verify oci://registry.k8s.io/security-profiles-operator/security-profiles-operator-amd64:$VERSION \
    --repo kubernetes-sigs/security-profiles-operator \
    --signer-workflow kubernetes-sigs/security-profiles-operator/.github/workflows/provenance.yml \
    --source-ref refs/tags/$VERSION \
    --deny-self-hosted-runners
```

The manifest list is no subject, but its platform images are the per-arch
images, with the same digests, so
`oci://registry.k8s.io/security-profiles-operator/security-profiles-operator@$DIGEST`
verifies as well, with the digest of the per-arch image, the `$DIGEST` of
[container image](#container-image).

The provenance is also attached as OCI referrer to each per-arch image, and
the image promoter carries it to the per-arch repositories on
`registry.k8s.io`. cosign verifies it with the GitHub identity, and the
provenance names the workflow that built the images:

```console
> cosign verify-attestation \
    --type https://slsa.dev/provenance/v1 \
    --certificate-identity https://github.com/kubernetes-sigs/security-profiles-operator/.github/workflows/provenance.yml@refs/tags/$VERSION \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-github-workflow-repository kubernetes-sigs/security-profiles-operator \
    --certificate-github-workflow-ref refs/tags/$VERSION \
    --certificate-github-workflow-trigger release \
    registry.k8s.io/security-profiles-operator/security-profiles-operator-amd64@$DIGEST |
    jq -r '.payload | @base64d | fromjson | .predicate.buildDefinition.externalParameters.workflow.path'
```

It prints `.github/workflows/image-reproducible.yml`. The identity alone is not
enough: the repository, ref and trigger of the certificate show that a release
of this repository signed it, see
[the provenance signer](release.md#the-provenance-signer). In staging the
provenance is attached to the digest in its per-arch repository and in the one
of the manifest list, so the same command works with both staging references.
The Cloud Build provenance of the images stays next to it, at L1.

## Verification summaries

The image promoter publishes a
[SLSA verification summary][promoter-summaries] (VSA) for every digest it
promotes, index and platform manifests alike. It is an in-toto statement with
the predicate type `https://slsa.dev/verification_summary/v1`, attached as OCI
referrer next to the promoted digest, and says that the staging attestations
of the digest passed the provenance policy of this project, and at which SLSA
build level. Consumers that trust the promoter can verify this one summary
instead of the provenance of every build, see
[enforcing the verification in a cluster](#enforcing-the-verification-in-a-cluster).
The [promoter's guide][promoter-guide] explains how projects get summaries for
their images.

### What a summary says

To print the summary of the manifest list of a release, verify it with its
signer and decode the statement:

```console
> cosign verify-attestation \
    --type https://slsa.dev/verification_summary/v1 \
    --certificate-identity promoter-summaries@k8s-releng-prod.iam.gserviceaccount.com \
    --certificate-oidc-issuer https://accounts.google.com \
    registry.k8s.io/security-profiles-operator/security-profiles-operator:$VERSION |
    jq '.payload | @base64d | fromjson | .predicate'
```

It looks like this, without its input attestations:

```json
{
  "verifier": {
    "id": "https://k8s.io/promo-tools/verifier/v1",
    "version": { "kpromo": "…" }
  },
  "timeVerified": "…",
  "resourceUri": "registry.k8s.io/security-profiles-operator/security-profiles-operator@sha256:…",
  "policy": {
    "uri": "git+https://github.com/kubernetes/k8s.io#registry.k8s.io/manifests/k8s-staging-sp-operator/promoter-manifest.yaml",
    "digest": { "gitCommit": "…" }
  },
  "verificationResult": "PASSED",
  "verifiedLevels": ["SLSA_BUILD_LEVEL_3", "K8S_PROMOTION_MANIFEST_REVIEWED"],
  "slsaVersion": "1.0"
}
```

- `verifier.id` identifies the promoter. Other summaries of the digest, for
  example one attached in staging, don't count.
- `resourceUri` is the `registry.k8s.io` reference of the digest, which is
  also the subject of the statement.
- `policy` is the promoter manifest with the provenance policy and the commit
  it was read at.
- `verificationResult` is `PASSED`, or `FAILED` when the attestations of the
  digest don't satisfy the policy.
- `verifiedLevels` holds the SLSA build level the policy verified, from
  `SLSA_BUILD_LEVEL_1` to `SLSA_BUILD_LEVEL_3`, see [levels](#levels), and
  `K8S_PROMOTION_MANIFEST_REVIEWED`. A passed summary without a verified level
  has `SLSA_BUILD_LEVEL_UNEVALUATED` instead, which is why the commands below
  match the numbered levels only, and a failed summary has only `FAILED`.
- `inputAttestations` lists the staging attestations the policy accepted, by
  digest, which the promoter carried to `registry.k8s.io` as well.

### Verify a summary

The promoter signs its summaries with an identity of their own,
`promoter-summaries@k8s-releng-prod.iam.gserviceaccount.com`, which only the
production promotion jobs can use. Verify a summary by its predicate type and
that identity, and check that the promoter is its verifier, that it passed
and at which level:

```console
> cosign verify-attestation \
    --type https://slsa.dev/verification_summary/v1 \
    --certificate-identity promoter-summaries@k8s-releng-prod.iam.gserviceaccount.com \
    --certificate-oidc-issuer https://accounts.google.com \
    registry.k8s.io/security-profiles-operator/security-profiles-operator:$VERSION |
    jq -e '.payload | @base64d | fromjson | .predicate
      | select(.verifier.id == "https://k8s.io/promo-tools/verifier/v1")
      | .verificationResult == "PASSED" and
        any(.verifiedLevels[]; test("^SLSA_BUILD_LEVEL_[123]$"))'
true
```

Both the signer and the verifier ID matter: `verifier.id` is just a field of
the statement, only the signature of `promoter-summaries` makes it the
promoter's. `PASSED` alone only says that the digest was promoted from a
reviewed promoter manifest, so check the level as well. The command accepts
any level, require `SLSA_BUILD_LEVEL_3` instead where only level 3 will do.

The [SLSA verifier][slsa-verifier] checks the same on a downloaded summary,
here at level 3, bound to the digest:

```console
> cosign download attestation \
    --predicate-type https://slsa.dev/verification_summary/v1 \
    registry.k8s.io/security-profiles-operator/security-profiles-operator:$VERSION >vsa.sigstore.json
> slsa-verifier vsa \
    --verifier 'https://k8s.io/promo-tools/verifier/v1=sigstore::https://accounts.google.com::promoter-summaries@k8s-releng-prod.iam.gserviceaccount.com' \
    --level SLSA_BUILD_LEVEL_3 \
    --subject "$(crane digest registry.k8s.io/security-profiles-operator/security-profiles-operator:$VERSION)" \
    vsa.sigstore.json
```

### Levels

A digest gets the highest level of its provenances that pass the policy. The
manifest list has no provenance of its own and gets the level of its platform
manifests:

| Artifact on `registry.k8s.io` | Level | Provenance |
| ----------------------------- | ----- | ---------- |
| Container image: manifest list, platform manifests and per-arch images | `SLSA_BUILD_LEVEL_3` | GitHub (plus Cloud Build at level 1), see [per-arch images](release.md#per-arch-images) |
| `spoc` | `SLSA_BUILD_LEVEL_3` | GitHub, see [OCI artifacts](release.md#oci-artifacts) |
| Helm chart | `SLSA_BUILD_LEVEL_3` | GitHub, see [OCI artifacts](release.md#oci-artifacts) |
| Operator bundle and catalog | `SLSA_BUILD_LEVEL_3` | GitHub (plus Cloud Build at level 1), see [bundle and catalog](release.md#bundle-and-catalog) |
| Security profiles | `SLSA_BUILD_LEVEL_3` | GitHub of `main` (plus Cloud Build at level 1), see [security profiles](release.md#security-profiles) |

The container images, bundle and catalog of a release that had to be
promoted without the GitHub provenance only reach level 1, see
[per-arch images](release.md#per-arch-images). So do the bundles, catalogs
and profiles promoted before they got the GitHub provenance, see
[older releases](#older-releases), because a digest keeps the summary of its
first promotion.

### Missing and failed summaries

The promoter writes the summary of a digest once, when it promotes it or, if
that failed, in the repair of a later run, and never replaces it:

- A digest that doesn't satisfy the policy keeps a `FAILED` summary, like the
  images of the [older releases](#older-releases).
- A digest promoted before the promoter wrote summaries has none, unless a
  later repair reached it while its staging images still existed.

A cluster policy that requires a passed summary rejects both.

## Enforcing the verification in a cluster

The commands of this page verify by hand. The
[nri-supply-chain][nri-supply-chain] plugin enforces the same on the nodes: it
is an [NRI][nri] plugin for CRI-O and containerd that verifies the signatures
and attestations of an image before the runtime creates a container from it.
For images on `registry.k8s.io` it can rely on the verification summary of the
image promoter instead of evaluating the attestations of every build. A policy
rule for the images of this project trusts the promoter as verifier, bound to
the identity that signs its summaries, and requires a summary:

```json
{
  "rules": [
    {
      "images": ["registry.k8s.io/security-profiles-operator/**"],
      "trust": {
        "issuers": ["https://accounts.google.com"],
        "sanPatterns": [
          "krel-trust@k8s-releng-prod.iam.gserviceaccount.com",
          "promoter-summaries@k8s-releng-prod.iam.gserviceaccount.com"
        ],
        "verifiers": [
          {
            "id": "https://k8s.io/promo-tools/verifier/v1",
            "identities": [
              {
                "issuer": "https://accounts.google.com",
                "sanPattern": "promoter-summaries@k8s-releng-prod.iam.gserviceaccount.com"
              }
            ]
          }
        ]
      },
      "vsa": { "missingPolicy": "deny", "minimumLevel": 1 }
    }
  ]
}
```

The plugin reads the summary from the repository the image is pulled from,
which is where the promoter writes the summaries of the manifest list and its
platform manifests. `vsa.missingPolicy: deny` rejects every digest without a
passed summary of the promoter, which includes the
[older releases](#older-releases), so roll the rule out in the `warn` mode of
the plugin first, which only logs. `vsa.minimumLevel: 1` rejects summaries
that claim no level, see [levels](#levels). The rule matches the operator
bundle and catalog too, which OLM runs on the nodes and which only reach
level 3 if they were promoted with the GitHub provenance, see
[older releases](#older-releases), so require level 3 in a rule for the
operator image only as long as older bundles and catalogs are in use. An
`exclude` pattern that matches the images, like `registry.k8s.io/**`, skips
the rule. The policy documentation of the plugin explains the rule and its
options in
[images promoted to registry.k8s.io][nri-supply-chain-promoted], and its
[deployment documentation][nri-supply-chain-deployment] how to install the
plugin and which system images to exclude.

Other verifiers work as well, as long as they pin both the verifier ID and the
signer of the summary, for example `slsa-verifier vsa`, see
[verify a summary](#verify-a-summary).

## Command line binaries

`spoc` is built and signed by the [`build`](../.github/workflows/build.yml)
workflow for `amd64`, `arm64`, `ppc64le` and `s390x`. Download the binary, its
signature and the provenance from the [release page][releases], then verify
both, here for `amd64`:

```console
> cosign verify-blob \
    --certificate-identity https://github.com/kubernetes-sigs/security-profiles-operator/.github/workflows/build.yml@refs/tags/$VERSION \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --bundle spoc.amd64.sigstore.json \
    spoc.amd64
> gh attestation verify spoc.amd64 \
    --bundle spoc.intoto.jsonl \
    --repo kubernetes-sigs/security-profiles-operator \
    --signer-workflow kubernetes-sigs/security-profiles-operator/.github/workflows/provenance.yml \
    --source-ref refs/tags/$VERSION \
    --deny-self-hosted-runners
```

The release also carries a `.sha512` sum per binary.

## Software bill of materials

The SBOM of the Go modules of the binaries, `spoc.spdx.json`, is signed and
covered by the same provenance. So is `spoc-native.spdx.json`, the SBOM of the
C libraries the binaries link statically, like libseccomp and libbpf, whose
versions come from the nix build. Verify it with the same commands:

```console
> cosign verify-blob \
    --certificate-identity https://github.com/kubernetes-sigs/security-profiles-operator/.github/workflows/build.yml@refs/tags/$VERSION \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --bundle spoc.spdx.json.sigstore.json \
    spoc.spdx.json
> gh attestation verify spoc.spdx.json \
    --bundle spoc.intoto.jsonl \
    --repo kubernetes-sigs/security-profiles-operator \
    --signer-workflow kubernetes-sigs/security-profiles-operator/.github/workflows/provenance.yml \
    --source-ref refs/tags/$VERSION \
    --deny-self-hosted-runners
```

## Helm chart

The chart archive attached to the release is signed by the
[`helm-chart-package`](../.github/workflows/helm-chart-package.yaml) workflow:

```console
> cosign verify-blob \
    --certificate-identity https://github.com/kubernetes-sigs/security-profiles-operator/.github/workflows/helm-chart-package.yaml@refs/tags/$VERSION \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --bundle security-profiles-operator-${VERSION#v}.tgz.sigstore.json \
    security-profiles-operator-${VERSION#v}.tgz
> gh attestation verify security-profiles-operator-${VERSION#v}.tgz \
    --bundle security-profiles-operator-${VERSION#v}.intoto.jsonl \
    --repo kubernetes-sigs/security-profiles-operator \
    --signer-workflow kubernetes-sigs/security-profiles-operator/.github/workflows/provenance.yml \
    --source-ref refs/tags/$VERSION \
    --deny-self-hosted-runners
```

The chart is also published as an OCI artifact to `registry.k8s.io`, which
holds the same archive, see
[OCI artifacts on `registry.k8s.io`](#oci-artifacts-on-registryk8sio).

## OCI artifacts on `registry.k8s.io`

A release publishes `spoc` and the Helm chart to `registry.k8s.io` too, with
exceptions for v1.1.0 and [older releases](#older-releases). They
are the files of the release page in OCI manifests, see
[OCI artifacts](release.md#oci-artifacts): every platform manifest of
`registry.k8s.io/security-profiles-operator/spoc:$VERSION` has the binary as
its only layer, and the layer of
`registry.k8s.io/security-profiles-operator/charts/security-profiles-operator:${VERSION#v}`
is the chart archive. The digests of the index, the platform manifests and the
chart manifest are subjects of the provenance of the release assets, so the
same command verifies them, with the GitHub attestation store or with
`--bundle` and the provenance of the release page:

```console
> gh attestation verify oci://registry.k8s.io/security-profiles-operator/spoc:$VERSION \
    --repo kubernetes-sigs/security-profiles-operator \
    --signer-workflow kubernetes-sigs/security-profiles-operator/.github/workflows/provenance.yml \
    --source-ref refs/tags/$VERSION \
    --deny-self-hosted-runners
> gh attestation verify oci://registry.k8s.io/security-profiles-operator/charts/security-profiles-operator:${VERSION#v} \
    --repo kubernetes-sigs/security-profiles-operator \
    --signer-workflow kubernetes-sigs/security-profiles-operator/.github/workflows/provenance.yml \
    --source-ref refs/tags/$VERSION \
    --deny-self-hosted-runners
```

The layer digests are the sha256 sums of the files, so a binary can also be
downloaded by digest and checked like a file of the release page, for
example with [oras](https://oras.land):

```console
> oras pull --platform linux/amd64 registry.k8s.io/security-profiles-operator/spoc:$VERSION
```

The provenance is also attached as OCI referrer to the `spoc` index and the
chart manifest, next to the SBOMs (`https://spdx.dev/Document/v3`) the staging
build attests for them: for `spoc` the `spoc.spdx.json` and
`spoc-native.spdx.json` of the release page, for the chart an SBOM of the
chart archive and the files in it. The `spoc` SBOM is a few hundred kilobytes,
so the second command only prints the names of the SBOMs:

```console
> cosign verify-attestation \
    --type https://slsa.dev/provenance/v1 \
    --certificate-identity https://github.com/kubernetes-sigs/security-profiles-operator/.github/workflows/provenance.yml@refs/tags/$VERSION \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-github-workflow-repository kubernetes-sigs/security-profiles-operator \
    --certificate-github-workflow-ref refs/tags/$VERSION \
    --certificate-github-workflow-trigger release \
    registry.k8s.io/security-profiles-operator/spoc:$VERSION
> cosign verify-attestation \
    --type https://spdx.dev/Document/v3 \
    --certificate-identity sp-operator-sa@k8s-staging-images.iam.gserviceaccount.com \
    --certificate-oidc-issuer https://accounts.google.com \
    registry.k8s.io/security-profiles-operator/spoc:$VERSION |
    jq -r '.payload | @base64d | fromjson | .predicate
      | .name // (."@graph"[]? | select(.type == "SpdxDocument") | .name)'
```

The platform manifests of `spoc` only have their referrers in the staging
registry, `us-central1-docker.pkg.dev/k8s-staging-images/sp-operator/spoc`,
because the promoter manifest doesn't list them, see
[attestations on registry.k8s.io](release.md#attestations-on-registryk8sio).
The GitHub attestation store covers them wherever they are pulled from.

## Security profiles

The base profiles are published as
`registry.k8s.io/security-profiles-operator/base/<runtime>:<version>`, for
`runc` and `crun` and with the runtime version the profile was recorded
against as the tag, see [base profiles](release-baseprofiles.md). List the
published versions of a runtime with:

```console
> crane ls registry.k8s.io/security-profiles-operator/base/runc
```

`spoc pull` and base profiles referenced with the `oci://` prefix verify the
signature of a profile by default and fail when it is missing or does not
match. Profiles from `registry.k8s.io/security-profiles-operator/` and from
the staging registry
`us-central1-docker.pkg.dev/k8s-staging-images/sp-operator/` have to be signed
by one of the identities which publish them:

- certificate identity:
  `krel-trust@k8s-releng-prod.iam.gserviceaccount.com` (the image promoter) or
  `sp-operator-sa@k8s-staging-images.iam.gserviceaccount.com` (the staging
  build)
- issuer: `https://accounts.google.com`

That applies as long as the allowed identity and issuer regexps are left at
their default `.*`: `spoc pull` without `--allowed-identity-regexp` and
`--allowed-oidc-issuer-regexp`, and the SPOD without
`spec.security.allowedIdentityRegexp` and `allowedOidcIssuerRegexp`. Any
other value is used as given, for all registries. Profiles from other
registries are verified against the configured regexps, and with the default
`.*` any valid signature is accepted, which only proves that somebody signed
the profile. `spoc pull` and the daemon log a warning then. To verify the
official profiles explicitly:

```console
> spoc pull \
    --allowed-identity-regexp '^(krel-trust@k8s-releng-prod|sp-operator-sa@k8s-staging-images)\.iam\.gserviceaccount\.com$' \
    --allowed-oidc-issuer-regexp '^https://accounts\.google\.com$' \
    registry.k8s.io/security-profiles-operator/base/runc:<version>
```

The provenance and the SBOM of a promoted profile verify like the ones of the
[container image](#container-image), with the build identity and the
reference of the profile. Only versions that were promoted under the
provenance policy of this project carry them on `registry.k8s.io`. Earlier
ones only have the `krel-trust` signature there, and their attestations, if
the build attested them, in the staging registry while it keeps them.
`cosign tree` shows what a version carries.

See [the CLI documentation](cli.md#pull-security-profiles-from-oci-registries)
for pulling from other registries.

## Staging images

The images in the staging registry carry the full set of attestations, which
[release.md](release.md#staging-attestations) documents together with the
commands to verify them.

## Older releases

v1.1.0 and the releases before it predate most of this page:

- Their container images have no GitHub provenance, there is no
  `images.intoto.jsonl` and `spoc` is not on `registry.k8s.io`.
- On `registry.k8s.io` they only have the `krel-trust` signature of the image
  promoter, see [container image](#container-image). The promoter carried no
  attestations for them, and they have no passed
  [verification summary](#verification-summaries): their staging provenance
  names the builder of a former build job, which the provenance policy of
  this project doesn't trust, see
  [attestations on registry.k8s.io](release.md#attestations-on-registryk8sio).
  A cluster policy that requires the summary rejects them.
- Their staging attestations can be verified by digest in the staging
  registry, with the commands of [container image](#container-image) and the
  staging reference
  `us-central1-docker.pkg.dev/k8s-staging-images/sp-operator/security-profiles-operator-amd64@$DIGEST`,
  where `$DIGEST` is what `crane digest` prints for the promoted per-arch
  image, until the staging registry deletes the images, 90 days after their
  build.
- The provenance of the release assets of v1.1.0 was signed by the build jobs
  themselves. Verify it with the commands of
  [command line binaries](#command-line-binaries) and
  [Helm chart](#helm-chart), but with the `build.yml` signer workflow, or for
  the chart archive with the `helm-chart-package.yaml` one and without
  `--bundle`.
- The Helm chart of v1.1.0 on `registry.k8s.io` was packaged separately from
  the release archive, so its digest differs from the archive and it has the
  staging provenance of the container images instead.
- v1.1.0 has no `spoc-native.spdx.json`. The releases before it name the
  SBOM `spoc.spdx`, with a signature in another format (`spoc.spdx.bundle`,
  or `spoc.spdx.sig` and `spoc.spdx.cert`) or without any SBOM, so the
  commands of [software bill of materials](#software-bill-of-materials) don't
  work for them as they are.
- v1.1.1 and the releases before it attest their SBOMs as
  `https://spdx.dev/Document`, so use that `--type` for them.
- The operator bundles and catalogs of v1.1.1 and the releases before it,
  and the security profiles promoted with them, only have the Cloud Build
  provenance and reach level 1, see [levels](#levels).
- Releases before v1.1.0 have no provenance and no Helm chart on
  `registry.k8s.io`. v1.0.0 and v1.0.1 name the signature of a binary
  `spoc.amd64.bundle`, v0.10.0 and older ship `spoc.amd64.sig` and
  `spoc.amd64.cert` instead.

[attestations]: https://docs.github.com/en/actions/concepts/security/artifact-attestations
[cosign]: https://github.com/sigstore/cosign
[crane]: https://github.com/google/go-containerregistry/blob/main/cmd/crane/README.md
[gh]: https://cli.github.com
[nri]: https://github.com/containerd/nri
[nri-supply-chain]: https://github.com/saschagrunert/nri-supply-chain
[nri-supply-chain-deployment]: https://github.com/saschagrunert/nri-supply-chain/blob/main/docs/deployment.md
[nri-supply-chain-promoted]: https://github.com/saschagrunert/nri-supply-chain/blob/main/docs/policy.md#images-promoted-to-registryk8sio
[promoter]: https://github.com/kubernetes-sigs/promo-tools/blob/main/docs/image-promotion.md
[promoter-carry]: https://github.com/kubernetes-sigs/promo-tools/blob/main/docs/image-promotion.md#carrying-staging-attestations
[promoter-policies]: https://github.com/kubernetes-sigs/promo-tools/blob/main/docs/image-promotion.md#provenance-policies
[promoter-guide]: https://github.com/kubernetes-sigs/promo-tools/blob/main/docs/verification-summaries.md
[promoter-summaries]: https://github.com/kubernetes-sigs/promo-tools/blob/main/docs/image-promotion.md#verification-summaries
[releases]: https://github.com/kubernetes-sigs/security-profiles-operator/releases/latest
[sigstore]: https://www.sigstore.dev
[slsa]: https://slsa.dev
[slsa-l3]: https://slsa.dev/spec/v1.0/levels#build-l3
[slsa-verifier]: https://github.com/slsa-framework/verifier
