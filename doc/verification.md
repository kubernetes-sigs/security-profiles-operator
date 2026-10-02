# Verifying the released artifacts

Every artifact of a release is signed with [Sigstore][sigstore] keyless
signing, and the release assets also carry [SLSA][slsa] build provenance. This
page collects the verification commands for all of them, so a release only has
to link here.

The commands need [cosign][cosign] v3 or later, because the signatures use the
Sigstore bundle format that cosign v2 cannot read. The provenance checks of the
release assets use the [GitHub CLI][gh]. The examples verify the latest
release, set `VERSION` to the tag of the [release][releases] at hand:

```console
> export VERSION=$(gh release view -R kubernetes-sigs/security-profiles-operator --json tagName -q .tagName)
```

Releases up to v1.1.0 carry provenance that the build jobs signed themselves.
Verify it with the commands below, but with the `build.yml` signer workflow, or
for the chart archive with the `helm-chart-package.yaml` one and without
`--bundle`.

## What a release provides

| Artifact | Signature | Provenance | SBOM |
| -------- | --------- | ---------- | ---- |
| Container images on `registry.k8s.io` | yes, as `krel-trust` | carried; [GitHub](#github-provenance-of-the-container-images), by digest, after v1.1.0 | carried |
| `spoc` binaries | yes | yes | `spoc.spdx.json`, `spoc-native.spdx.json` |
| `spoc.spdx.json`, `spoc-native.spdx.json` | yes | yes | |
| Helm chart archive on the release page | yes | yes | |
| Helm chart on `registry.k8s.io` | yes, as `krel-trust` | yes, by digest, after v1.1.0 | carried, after v1.1.0 |
| `spoc` on `registry.k8s.io` (after v1.1.0) | yes, as `krel-trust` | yes, by digest | release page, carried |
| Security profiles on `registry.k8s.io` | yes | carried | carried |

"Carried" means that the build attaches it in staging and the image promoter
copies it next to the promoted digest on `registry.k8s.io`, in the repository
the promoter manifest lists the digest in (the per-arch repositories for the
container images), when the digest satisfies the provenance policy of this
project. That holds for digests promoted since the policy is in place
(2026-10-02), and for those promoted in the 14 days before, which the repair
phase of the promotion jobs fills in while they are still in staging. Older
digests only have it in staging, by digest, until the staging registry
deletes them. The staging registry is
`us-central1-docker.pkg.dev/k8s-staging-images/sp-operator`, where the build
attaches SLSA provenance and SPDX SBOMs to the images, profiles and charts it
publishes, and to the images a vulnerability scan, an OpenVEX document, the
build environment and the OpenSSF Scorecard result, as OCI referrers. To
`spoc` and the released chart, the release artifacts job attaches the GitHub
provenance and SBOMs, see [OCI artifacts](release.md#oci-artifacts). The
manifest list only gets a signature, and published profiles or charts whose
content differs from the repository get neither, see
[staging attestations](release.md#staging-attestations). The promotion keeps
the digests, so the attestations of a promoted artifact can be verified by its
digest in the staging registry, see [container image](#container-image).
Staging images are deleted after 90 days, after that the attestations of older
releases can't be verified anymore.

From kpromo v4.7.0 on, which the promotion jobs run since 2026-10-02, the
image promoter copies the staging attestations it accepts next to the promoted
digest in `registry.k8s.io` and can publish a SLSA verification summary for
it, when the promoter manifest of the project has a provenance policy. The
policy of this project is in place, in `warn` mode, so the attestations of the
artifacts promoted after it are on `registry.k8s.io` as well. The summaries
are still turned off, see
[attestations on registry.k8s.io](release.md#attestations-on-registryk8sio)
and [verification summaries](#verification-summaries). For artifacts promoted
before the policy, which includes all of v1.1.0, verifying in staging is the
only option.

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

The container images, the operator bundle and catalog, the Helm chart on
`registry.k8s.io` up to v1.1.0 and the security profiles are built on Cloud
Build and meet SLSA Build L1 only, apart from the per-arch images of releases,
see below. Their provenance is generated and signed by the build itself,
with the same service account as the build steps, so the build steps could
forge it. Its `runDetails.builder.id` therefore names the Cloud Build
configuration and service account of the staging project, not Google's build
platform, and its `buildType` points to the documentation of the built commit.
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
the per-arch images of releases after v1.1.0 SLSA Build L3 provenance as well,
see [GitHub provenance of the container images](#github-provenance-of-the-container-images).
Images built before the BuildKit image was pinned are not reproducible. To
rebuild the images of a commit yourself and compare them with its staging
images, with docker and buildx on a `linux/amd64` machine, like Cloud Build
and GitHub Actions (the build image is only published for it):

```console
> git checkout $COMMIT
> PUSH=false hack/image-cross.sh
> cat build/image-digests
> STAGING_WAIT=0 hack/ci/compare-staging-images.sh
```

## GitHub provenance of the container images

Releases after v1.1.0 attest their per-architecture images on GitHub too, no
such release exists yet. The
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
verifies as well, with the digest of the per-arch image:

```console
> DIGEST=$(crane digest registry.k8s.io/security-profiles-operator/security-profiles-operator-amd64:$VERSION)
```

The provenance is also attached as OCI referrer to each per-arch image in the
staging registry, in its own repository and in the one of the manifest list.
cosign verifies it with the GitHub identity, and the provenance names the
workflow that built the images:

```console
> cosign verify-attestation \
    --type https://slsa.dev/provenance/v1 \
    --certificate-identity https://github.com/kubernetes-sigs/security-profiles-operator/.github/workflows/provenance.yml@refs/tags/$VERSION \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-github-workflow-repository kubernetes-sigs/security-profiles-operator \
    --certificate-github-workflow-ref refs/tags/$VERSION \
    --certificate-github-workflow-trigger release \
    us-central1-docker.pkg.dev/k8s-staging-images/sp-operator/security-profiles-operator-amd64@$DIGEST |
    jq -r '.payload | @base64d | fromjson | .predicate.buildDefinition.externalParameters.workflow.path'
```

It prints `.github/workflows/image-reproducible.yml`. The identity alone is not
enough: the repository, ref and trigger of the certificate show that a release
of this repository signed it, see
[the provenance signer](release.md#the-provenance-signer). The image promoter
carries the provenance to the per-arch images on `registry.k8s.io` when it
promotes the release, so the same command works for them there as well, see
[attestations on registry.k8s.io](release.md#attestations-on-registryk8sio).
The Cloud Build provenance of the images stays next to it, at L1.

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

The provenance, SBOMs, vulnerability scan, VEX document and build environment
of a build are attached to the staging images. The image promoter copies them
along to `registry.k8s.io` for the images promoted after the provenance policy
of this project, not for v1.1.0 and older releases, see
[attestations on registry.k8s.io](release.md#attestations-on-registryk8sio).
The promotion keeps the digest of every image, so look up the digest of the
promoted image for your architecture and verify its attestations in the
staging registry, within 90 days of the build, after which staging images are
deleted:

```console
> DIGEST=$(crane digest --platform linux/amd64 \
    registry.k8s.io/security-profiles-operator/security-profiles-operator:$VERSION)
> cosign verify-attestation \
    --type https://slsa.dev/provenance/v1 \
    --certificate-identity sp-operator-sa@k8s-staging-images.iam.gserviceaccount.com \
    --certificate-oidc-issuer https://accounts.google.com \
    us-central1-docker.pkg.dev/k8s-staging-images/sp-operator/security-profiles-operator-amd64@$DIGEST
```

In staging, images built after v1.1.0 also have the signature and
attestations of their platform images in the repository of the manifest list,
where container runtimes pull them from, so the same digest verifies as
`us-central1-docker.pkg.dev/k8s-staging-images/sp-operator/security-profiles-operator@$DIGEST`.

That doesn't carry over to `registry.k8s.io`. The image promoter copies the
attestations of the per-arch images into the per-arch repositories, so they
verify as
`registry.k8s.io/security-profiles-operator/security-profiles-operator-amd64@$DIGEST`,
by the build identity like in staging. It doesn't copy the attestations of the
platform manifests into the repository of the manifest list, because the
promoter manifest doesn't list their digests there. The
`registry.k8s.io/security-profiles-operator/security-profiles-operator`
repository gets what the promoter writes itself: its signature of the
manifest list and the platform manifests, its promotion record of the
manifest list and, once they are turned on, a
[verification summary](#verification-summaries) for the manifest list and for
each platform manifest.

That provenance is SLSA Build L1, see [SLSA build levels](#slsa-build-levels).

## Verification summaries

The image promoter can publish a SLSA verification summary (VSA) for every
digest it promotes, index and platform manifests alike: an in-toto statement
with the predicate type `https://slsa.dev/verification_summary/v1`, attached
as OCI referrer next to the promoted digest, which says that the staging
attestations of the digest passed the provenance policy of the project, and
at which SLSA build level. Consumers that trust the promoter can verify the
summary instead of the provenance of every build, for example the
nri-supply-chain plugin, which verifies the summary of the manifest list.

The promotion jobs run kpromo v4.7.0 with the provenance policy of this
project ([kubernetes/k8s.io#10012](https://github.com/kubernetes/k8s.io/pull/10012)),
and the identity that signs the summaries,
`promoter-summaries@k8s-releng-prod.iam.gserviceaccount.com`, exists, and
the production promotion jobs moved to their new account
([kubernetes/test-infra#37950](https://github.com/kubernetes/test-infra/pull/37950)).
The promoter doesn't write summaries yet though, the change that turns them
on is pending
([kubernetes/test-infra#37967](https://github.com/kubernetes/test-infra/pull/37967)).
The promotion jobs then also add summaries for the digests promoted in the 14
days before, older images only get one from a promoter run that repairs them
explicitly. Once they are on, verify a summary by its predicate type and the
identity of the promoter's summaries, and check that the promoter is its
verifier, that it passed and at which level:

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
```

The verifier ID `https://k8s.io/promo-tools/verifier/v1` is what identifies
the promoter, other summaries of the digest, for example one attached in
staging, don't count. `verifiedLevels` holds the one SLSA build level the
policy verified for the digest, and `K8S_PROMOTION_MANIFEST_REVIEWED`. So the
command accepts any level, require `SLSA_BUILD_LEVEL_3` instead where only
level 3 will do. The level is
`SLSA_BUILD_LEVEL_3` for `spoc`, the Helm chart and the per-arch images of
the releases after v1.1.0, and so for the platform manifests and the manifest
list of their container image, through their GitHub provenance, see
[OCI artifacts](release.md#oci-artifacts) and
[per-arch images](release.md#per-arch-images). It is `SLSA_BUILD_LEVEL_1` for
the operator bundle and catalog and the profiles, which only have the
provenance of Cloud Build. The artifacts of v1.1.0 and older releases don't
satisfy the policy, see
[attestations on registry.k8s.io](release.md#attestations-on-registryk8sio),
so a summary of them, if a repair writes one, has failed.
`resourceUri` is the `registry.k8s.io` reference of the digest, and
`inputAttestations` the staging attestations the policy accepted.

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

Older releases name the signature `spoc.amd64.bundle` and have no provenance.

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

The chart is also published as an OCI artifact to `registry.k8s.io`, see
[OCI artifacts on `registry.k8s.io`](#oci-artifacts-on-registryk8sio). Up to
v1.1.0 it was packaged separately from the release archive, so its digest
differs and it has the staging provenance of the
[container images](#container-image) instead, with the builder ID of the
former prow job, see
[attestations on registry.k8s.io](release.md#attestations-on-registryk8sio).

## OCI artifacts on `registry.k8s.io`

Releases after v1.1.0 publish `spoc` and the Helm chart to `registry.k8s.io`
too. They are the files of the release page in OCI manifests, see
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

In the staging registry the provenance is attached as OCI referrer to each
manifest, and the manifests are signed by the staging build, which also
attests the SBOMs (`https://spdx.dev/Document`) for them: for `spoc` the
`spoc.spdx.json` and `spoc-native.spdx.json` of the release page, for the
chart an SBOM of the chart archive and the files in it. The `spoc` SBOM is a
few hundred kilobytes, so the second command only prints the names of the
SBOMs:

```console
> cosign verify-attestation \
    --type https://slsa.dev/provenance/v1 \
    --certificate-identity https://github.com/kubernetes-sigs/security-profiles-operator/.github/workflows/provenance.yml@refs/tags/$VERSION \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-github-workflow-repository kubernetes-sigs/security-profiles-operator \
    --certificate-github-workflow-ref refs/tags/$VERSION \
    --certificate-github-workflow-trigger release \
    us-central1-docker.pkg.dev/k8s-staging-images/sp-operator/spoc:$VERSION
> cosign verify-attestation \
    --type https://spdx.dev/Document \
    --certificate-identity sp-operator-sa@k8s-staging-images.iam.gserviceaccount.com \
    --certificate-oidc-issuer https://accounts.google.com \
    us-central1-docker.pkg.dev/k8s-staging-images/sp-operator/spoc:$VERSION |
    jq -r '.payload | @base64d | fromjson | .predicate
      | .name // (."@graph"[]? | select(.type == "SpdxDocument") | .name)'
```

The image promoter copies the referrers along to `registry.k8s.io` when it
promotes the release, see
[attestations on registry.k8s.io](release.md#attestations-on-registryk8sio).

## Security profiles

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
    registry.k8s.io/security-profiles-operator/base/runc:v1.5.1
```

See [the CLI documentation](cli.md#pull-security-profiles-from-oci-registries)
for pulling from other registries.

## Staging images

The images in the staging registry carry the full set of attestations, which
[release.md](release.md#staging-attestations) documents together with the
commands to verify them.

[attestations]: https://docs.github.com/en/actions/concepts/security/artifact-attestations
[cosign]: https://github.com/sigstore/cosign
[gh]: https://cli.github.com
[releases]: https://github.com/kubernetes-sigs/security-profiles-operator/releases/latest
[sigstore]: https://www.sigstore.dev
[slsa]: https://slsa.dev
[slsa-l3]: https://slsa.dev/spec/v1.0/levels#build-l3
