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
| Container images on `registry.k8s.io` | yes, as `krel-trust` | staging only | staging only |
| `spoc` binaries | yes | yes | `spoc.spdx.json` |
| `spoc.spdx.json` | yes | yes | |
| Helm chart archive on the release page | yes | yes | |
| Helm chart on `registry.k8s.io` | staging only | staging only | |
| Security profiles on `registry.k8s.io` | yes | staging only | |

"Staging only" means the artifact carries it in
`us-central1-docker.pkg.dev/k8s-staging-images/sp-operator`, where the build
attaches SLSA provenance, an SPDX SBOM, a vulnerability scan, an OpenVEX
document, the build environment and the OpenSSF Scorecard result as OCI
referrers. The image promotion does not copy those to `registry.k8s.io` yet,
see [staging attestations](release.md#staging-attestations).

## SLSA build levels

The `spoc` binaries, their SBOM and the Helm chart archive on the release page
are built on GitHub Actions and meet [SLSA Build L3][slsa-l3]. The build jobs
hold no signing identity and no write access. They only pass the digests of
their outputs to the isolated reusable
[`provenance`](.github/workflows/provenance.yml) workflow, which generates and
signs the provenance as a [GitHub artifact attestation][attestations]. Separate
jobs that run no repository code sign the artifacts and attach them to the
release.

The container images, the operator bundle and catalog, the Helm chart on
`registry.k8s.io` and the security profiles are built on Cloud Build and stay
at SLSA Build L2. Their provenance is signed with the same service account and
in the same build as the build steps, so the build steps could forge it.

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

The provenance, SBOM, vulnerability scan, VEX document and build environment of
a build are attached to the staging images and are not copied to
`registry.k8s.io` yet, see
[staging attestations](release.md#staging-attestations).

## Command line binaries

`spoc` is built and signed by the [`build`](.github/workflows/build.yml)
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
    --source-ref refs/tags/$VERSION
```

The release also carries a `.sha512` sum per binary.

Older releases name the signature `spoc.amd64.bundle` and have no provenance.

## Software bill of materials

The SBOM of the binaries, `spoc.spdx.json`, is signed and covered by the same
provenance:

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
    --source-ref refs/tags/$VERSION
```

## Helm chart

The chart archive attached to the release is signed by the
[`helm-chart-package`](.github/workflows/helm-chart-package.yaml) workflow:

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
    --source-ref refs/tags/$VERSION
```

The chart is also published as an OCI artifact to `registry.k8s.io`. It is
packaged separately from the release archive, so its digest differs, and its
signature currently stays in the staging registry, see
[installation using helm](installation.md#installation-using-helm).

## Security profiles

`spoc pull` verifies the signature of a profile by default and fails when it is
missing or does not match, so no extra command is needed. See
[the CLI documentation](cli.md#pull-security-profiles-from-oci-registries) for
the available identities and for pulling from other registries.

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
