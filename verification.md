# Verifying the released artifacts

Every artifact of a release is signed with [Sigstore][sigstore] keyless
signing, and the release assets also carry [SLSA][slsa] build provenance. This
page collects the verification commands for all of them, so a release only has
to link here.

The commands need [cosign][cosign] v3 or later, because the signatures use the
Sigstore bundle format that cosign v2 cannot read. The provenance checks of the
release assets use [slsa-verifier][slsa-verifier]. The examples verify the
latest release, set `VERSION` to the tag of the [release][releases] at hand:

```console
> export VERSION=$(gh release view -R kubernetes-sigs/security-profiles-operator --json tagName -q .tagName)
```

Releases up to v1.1.0 carry GitHub build provenance from the build jobs
instead. Verify it with the [GitHub CLI][gh], here for `spoc.amd64`. The same
command works for `spoc.spdx.json`, and for the chart archive without
`--bundle` and with the `helm-chart-package.yaml` signer workflow:

```console
> gh attestation verify spoc.amd64 \
    --bundle spoc.intoto.jsonl \
    --repo kubernetes-sigs/security-profiles-operator \
    --signer-workflow kubernetes-sigs/security-profiles-operator/.github/workflows/build.yml \
    --source-ref refs/tags/$VERSION
```

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
their outputs to the [SLSA GitHub generator][slsa-generator], whose isolated
reusable workflow generates and signs the provenance. Separate jobs that run no
repository code sign the artifacts and attach them to the release.

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
> slsa-verifier verify-artifact spoc.amd64 \
    --provenance-path spoc.intoto.jsonl \
    --source-uri github.com/kubernetes-sigs/security-profiles-operator \
    --source-tag $VERSION
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
> slsa-verifier verify-artifact spoc.spdx.json \
    --provenance-path spoc.intoto.jsonl \
    --source-uri github.com/kubernetes-sigs/security-profiles-operator \
    --source-tag $VERSION
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
> slsa-verifier verify-artifact security-profiles-operator-${VERSION#v}.tgz \
    --provenance-path security-profiles-operator-${VERSION#v}.intoto.jsonl \
    --source-uri github.com/kubernetes-sigs/security-profiles-operator \
    --source-tag $VERSION
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

[cosign]: https://github.com/sigstore/cosign
[gh]: https://cli.github.com
[releases]: https://github.com/kubernetes-sigs/security-profiles-operator/releases/latest
[sigstore]: https://www.sigstore.dev
[slsa]: https://slsa.dev
[slsa-generator]: https://github.com/slsa-framework/slsa-github-generator
[slsa-l3]: https://slsa.dev/spec/v1.0/levels#build-l3
[slsa-verifier]: https://github.com/slsa-framework/slsa-verifier
