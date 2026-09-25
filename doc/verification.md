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
| Container images on `registry.k8s.io` | yes, as `krel-trust` | staging only, by digest | staging only, by digest |
| `spoc` binaries | yes | yes | `spoc.spdx.json`, `spoc-native.spdx.json` |
| `spoc.spdx.json`, `spoc-native.spdx.json` | yes | yes | |
| Helm chart archive on the release page | yes | yes | |
| Helm chart on `registry.k8s.io` | staging only | staging only | |
| Security profiles on `registry.k8s.io` | yes | staging only | |

"Staging only" means the artifact carries it in
`us-central1-docker.pkg.dev/k8s-staging-images/sp-operator`, where the build
attaches SLSA provenance, SPDX SBOMs of the Go modules and of the statically
linked C libraries, a vulnerability scan, an OpenVEX document, the build
environment and the OpenSSF Scorecard result as OCI referrers. The image
promotion does not copy those to `registry.k8s.io` yet, see
[staging attestations](release.md#staging-attestations). The promotion keeps
the digests though, so the attestations of a promoted image can be verified by
its digest in the staging registry, see [container image](#container-image).

## SLSA build levels

The `spoc` binaries, their SBOMs and the Helm chart archive on the release
page are built on GitHub Actions and meet [SLSA Build L3][slsa-l3]. The build
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
`registry.k8s.io` and the security profiles are built on Cloud Build and meet
SLSA Build L1 only. Their provenance is generated and signed by the build
itself, with the same service account as the build steps, so the build steps
could forge it. Its `runDetails.builder.id` therefore names the Cloud Build
configuration and service account of the staging project, not Google's build
platform, and its `buildType` points to the documentation of the built commit.
The build toolchain they compile with, `quay.io/security-profiles-operator/build`,
is built without caches on `main` and signed and attested by a job of the
[`build`](../.github/workflows/build.yml) workflow that runs no repository code.
The image builds only substitute from `cache.nixos.org`, whatever the build
image configures. Build images pinned in `Dockerfile` before that change were
still built with the old workflow, which used the GitHub Actions cache and
the Cachix cache, until `BUILD_IMAGE` is pinned to an image built by it.

## Container image

The images on `registry.k8s.io` are promoted by the Kubernetes image promoter,
which signs them as `krel-trust`:

```console
> cosign verify \
    --certificate-identity krel-trust@k8s-releng-prod.iam.gserviceaccount.com \
    --certificate-oidc-issuer https://accounts.google.com \
    registry.k8s.io/security-profiles-operator/security-profiles-operator:$VERSION
```

The same command works for the operator bundle, the catalog and the promoted
`base/*` profiles by replacing the image name.

The provenance, SBOMs, vulnerability scan, VEX document and build environment
of a build are attached to the staging images and are not copied to
`registry.k8s.io` yet, see
[staging attestations](release.md#staging-attestations). The promotion keeps
the digest of every image, so look up the digest of the promoted image for
your architecture and verify its attestations in the staging registry:

```console
> DIGEST=$(crane digest --platform linux/amd64 \
    registry.k8s.io/security-profiles-operator/security-profiles-operator:$VERSION)
> cosign verify-attestation \
    --type https://slsa.dev/provenance/v1 \
    --certificate-identity sp-operator-sa@k8s-staging-images.iam.gserviceaccount.com \
    --certificate-oidc-issuer https://accounts.google.com \
    us-central1-docker.pkg.dev/k8s-staging-images/sp-operator/security-profiles-operator-amd64@$DIGEST
```

That provenance is SLSA Build L1, see [SLSA build levels](#slsa-build-levels).

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

The chart is also published as an OCI artifact to `registry.k8s.io`. It is
packaged separately from the release archive, so its digest differs, and its
signature currently stays in the staging registry, see
[installation using helm](installation.md#installation-using-helm).

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
