# Releasing a new version of the security-profiles-operator

A new security-profiles-operator release can be done by overall three Pull Requests (PRs).
Please ensure that no other PRs got merged in between. This can be achieved by
opening a new `Release vx.y.z` issue and applying the `tide/merge-blocker` label
if appropriate.

The overall process should not take longer than a couple of minutes, but it is
required to have one of the repository [owners](../OWNERS) at hand to be able to
merge the PRs.

Run the `./hack/release.sh x.y.z` script by replacing the appropriate version.
The script basically:

- bumps the [`VERSION`](../VERSION) file to the target version
- changes the `images` `newName`/`newTag` fields of
  [./deploy/kustomize-deployment/kustomization.yaml](../deploy/kustomize-deployment/kustomization.yaml)
  from `us-central1-docker.pkg.dev/k8s-staging-images/sp-operator/security-profiles-operator` to
  `registry.k8s.io/security-profiles-operator/security-profiles-operator` (`newName`) and the
  corresponding tag (`newTag`).
- changes the `image` in the `CatalogSource` in the same way at
  [./examples/olm/install-resources.yaml](/examples/olm/install-resources.yaml)
- changes the image of the webhook overlay
  [./deploy/overlays/webhook/kustomization.yaml](../deploy/overlays/webhook/kustomization.yaml)
  and the image, tag and pull policy in the Helm chart
  [values](../deploy/helm/values.yaml) in the same way
- changes [`hack/ci/e2e-olm.sh`](/hack/ci/e2e-olm.sh) and the e2e tests to
  use the released images from `registry.k8s.io` instead of the staging ones,
  for example `registry.k8s.io/security-profiles-operator/security-profiles-operator-catalog:vx.y.z`
  instead of
  `us-central1-docker.pkg.dev/k8s-staging-images/sp-operator/security-profiles-operator-catalog:latest`
- updates [./dependencies.yaml](../dependencies.yaml) `spo-current` version as
  well as its linked files. Run `make verify-dependencies` to verify the
  results.
- updates the versioned install manifests in
  [`installation.md`](installation.md) and the `spoc` image and version in
  [`cli.md`](cli.md)
- updates ./hack/deploy-localhost.patch to match the new deployment
- updates [./deploy/base/clusterserviceversion.yaml](../deploy/base/clusterserviceversion.yaml)
  to change `replaces` to the latest available version on OperatorHub as well as
  update the `containerImage`.
- runs `make bundle`

Create a new PR from the proposed changes and wait for the CI to succeed.

After this PR has been merged, we have to watch out the successful build of the
container image via the automatically triggered
`post-security-profiles-operator-push-image` post submit job in prow. All jobs of this
type can be found either on the commit status on the `main` branch or [in prow
directly](https://prow.k8s.io/?job=post-security-profiles-operator-push-image).

If the image got built successfully, tag the release. Tags created in the
GitHub UI are lightweight and unsigned, so check out the merged commit of the
first PR and run [`hack/tag-release.sh`](../hack/tag-release.sh). It creates
the signed, annotated tag `vx.y.z` for the version in the
[`VERSION`](../VERSION) file, which needs a git signing key
(`user.signingkey`, GPG or SSH with `gpg.format=ssh`), and verifies it with
`git verify-tag`. It refuses to tag a development version, a dirty tree or an
existing tag, and pushes nothing. Check the signature once more and push the
tag:

```console
> git verify-tag vx.y.z
> git push origin vx.y.z
```

Set `REMOTE` for the script to print the push command with another remote.
The `v*` tags have to be protected in the repository settings (a tag ruleset
which restricts their creation, update and deletion to the release managers),
since the release workflows trust a tag to be a reviewed release commit, and
the `post-security-profiles-operator-push-release-artifacts` job runs the
Cloud Build configuration of any pushed `v*` tag with the staging service
account.

Right after pushing the tag, [create the
release](https://github.com/kubernetes-sigs/security-profiles-operator/releases/new)
on GitHub from the pushed tag as a **pre-release** and add the release notes.
It stays a pre-release until its images are promoted. The changelog is
auto-generated based on PR labels and the configuration in
[`.github/release.yml`](../.github/release.yml). The introduction above it is
written by hand, start from
[`.github/release-notes-template.md`](../.github/release-notes-template.md) and
replace the version. The verification commands live in
[`verification.md`](verification.md), so the release only links them and they
stay correct for all releases.

Publishing the pre-release triggers the [`build`](../.github/workflows/build.yml)
workflow, which attaches the `spoc` binaries for all architectures and the
`spoc.spdx.json` and `spoc-native.spdx.json` SBOMs with their signatures
(`*.sigstore.json`), checksums and SLSA build provenance (`spoc.intoto.jsonl`)
to the release. The
[`helm-chart-package`](../.github/workflows/helm-chart-package.yaml) workflow
attaches the chart archive with its signature and provenance. Both also attach
the signed OCI layout of their artifacts (`spoc-oci-layout.tar` and
`security-profiles-operator-x.y.z-oci-layout.tar`), see
[OCI artifacts](#oci-artifacts). Nothing has to be built or uploaded by hand,
`make nix-spoc` is only meant for local builds. Verify that the files are
present. The reusable [`provenance`](../.github/workflows/provenance.yml)
workflow creates the provenance of both workflows, see
[SLSA build levels](verification.md#slsa-build-levels). If a job of them
fails, re-run only the failed jobs. `helm package` stamps the chart archive
with the current time, so re-running all jobs packages another archive, which
the `helm-chart-package` workflow does not upload because the release keeps
the assets of the first run.

The pushed tag triggers the `post-security-profiles-operator-push-release-artifacts`
post submit job in prow ([`cloudbuild-release.yaml`](../cloudbuild-release.yaml)),
which waits up to two hours for these release assets and publishes the `spoc`
binaries and the Helm chart from them to the staging registry, as
`us-central1-docker.pkg.dev/k8s-staging-images/sp-operator/spoc:vx.y.z` and
`us-central1-docker.pkg.dev/k8s-staging-images/sp-operator/charts/security-profiles-operator:x.y.z`.
If the job timed out because the release was created too late, run it again
from [prow](https://prow.k8s.io/?job=post-security-profiles-operator-push-release-artifacts).

If the job succeeded, we can create a second PR to [the k8s.io GitHub
repository](https://github.com/kubernetes/k8s.io). This PR promotes the built
container images (the manifest as well as the builds for `amd64`, `arm64` and
`ppc64le`), `spoc` and the Helm chart.

We can use the tool
[`kpromo`](https://github.com/kubernetes-sigs/promo-tools#kpromo) to allow
easier retrieval and modification of the necessary container image digests.
To run the tool from `$GOPATH/src/sigs.k8s.io/promo-tools`, just execute:

```bash
> export GITHUB_TOKEN=<YOUR_TOKEN>
> kpromo pr \
    --fork <YOUR_GH_USERNAME> \
    --project sp-operator \
    --tag v0.x.y \
    --tag 0.x.y
```

This will automatically create a PR in the k/k8s.io repository. The first
`--tag` picks up the images and `spoc`, the second one the Helm chart, which
is tagged with the version without the `v` prefix.

The promotion copies the images by digest. Their attestations are only copied
along by the image promoter once a provenance policy for this project is in
place, see [staging attestations](#staging-attestations). Once the promotion
PR is merged, check that the attestations still apply to what users install:
the per-architecture images on `registry.k8s.io` have to have the digests the
staging build attested, which the commands in
[verification.md](verification.md#container-image) verify for a release, and
`spoc` and the chart the digests of the GitHub provenance, see
[verification.md](verification.md#oci-artifacts-on-registryk8sio).

Then edit the release on GitHub, unset the pre-release and set it as the
latest release. That triggers the
[`spoc-reproducible`](../.github/workflows/spoc-reproducible.yml) workflow,
which checks that the released `spoc.amd64` is bit for bit the `spoc` of the
promoted image of the release.

After that, run the `./hack/back-to-dev.sh` script, which:

- bumps the [`VERSION`](../VERSION) file to the next patch version, but now
  including the suffix `-dev`, for example `1.1.1-dev` after `1.1.0`.
- points the images of the generated deployment manifests in
  [`deploy`](../deploy) and of the bundle
  [ClusterServiceVersion](../bundle/manifests/security-profiles-operator.clusterserviceversion.yaml)
  back to `us-central1-docker.pkg.dev/k8s-staging-images/sp-operator/security-profiles-operator:latest`,
  and sets the development version in them. It edits the generated files
  directly instead of running `make bundle`.
- comments the `registry.k8s.io` `newName`/`newTag` fields of
  [./deploy/kustomize-deployment/kustomization.yaml](../deploy/kustomize-deployment/kustomization.yaml)
  out again and the staging ones in, with the next version as commented
  `newTag`.
- points the catalog image of the OLM example manifest at
  [./examples/olm/install-resources.yaml](../examples/olm/install-resources.yaml),
  [`hack/ci/e2e-olm.sh`](../hack/ci/e2e-olm.sh),
  [`hack/deploy-localhost.patch`](../hack/deploy-localhost.patch), the e2e tests
  and the webhook overlay back to the staging registry, and the image of
  [`deploy/openshift-dev.yaml`](../deploy/openshift-dev.yaml) to the OpenShift
  internal registry.
- reverts the Helm chart [values](../deploy/helm/values.yaml) to the staging
  image with the `Always` pull policy.
- sets the development version in
  [./dependencies.yaml](../dependencies.yaml), the catalog preamble
  [`deploy/catalog-preamble.json`](../deploy/catalog-preamble.json), the
  [Helm chart](../deploy/helm/Chart.yaml) and its
  [README](../deploy/helm/README.md). Run `make verify-dependencies` to verify
  the results.

Create a new pull request in the OperatorHub.io [community
operators](https://github.com/k8s-operatorhub/community-operators) repository to
add the new version like in [this
PR](https://github.com/k8s-operatorhub/community-operators/pull/1672).

The last step about the release creation is to send a release announcement to
the [#security-profiles-operator Slack channel](https://kubernetes.slack.com/messages/security-profiles-operator).

## OCI artifacts

Releases publish the `spoc` binaries and the Helm chart to `registry.k8s.io`
as OCI artifacts, with the SLSA Build L3 provenance of the GitHub release
assets. GitHub Actions has no access to the staging registry and Cloud Build
can't produce L3 provenance, so the GitHub workflows build the OCI manifests
and attest their digests, and the staging job only verifies and copies them:

- The release workflows wrap the release assets with
  [`hack/oci-layout.sh`](../hack/oci-layout.sh) into OCI image layouts. `spoc`
  is an index with one manifest per architecture, each holding the binary as
  its only, uncompressed layer with the artifact type
  `application/vnd.k8s.security-profiles-operator.spoc.v1`, so the layer
  digest is the sha256 of the binary. The chart is the manifest which
  `helm push` writes for the chart archive. The manifests only depend on the
  wrapped files, the version, the commit and the commit time, which is their
  creation time, and for the chart on the helm version, which the workflow
  pins to the one of [`hack/push-chart.sh`](../hack/push-chart.sh). The
  digests of the manifests are provenance subjects next to the files, and the
  layouts without the layers are release assets.
- The `post-security-profiles-operator-push-release-artifacts` job runs
  [`hack/push-release-artifacts.sh`](../hack/push-release-artifacts.sh) for
  every `v*` tag. It waits for the release assets, restores the layouts,
  checks every blob against its digest and verifies with cosign that the
  provenance was signed by the `provenance.yml` workflow of the tag for the
  tagged commit and the GitHub release event, on a GitHub hosted runner, and
  that every manifest is one of its subjects. It pushes the manifests byte
  for byte, so they keep the attested digests, attaches the provenance bundle
  to the index and to every manifest as OCI referrer, the way cosign attaches
  Sigstore bundles, and signs them as `sp-operator-sa@k8s-staging-images`. An
  existing tag with another digest fails the job, the job can be run again.

The image promoter copies the manifests by digest like the images. The
`-dev` charts of `main` are still packaged and attested in the staging build
by [`hack/push-chart.sh`](../hack/push-chart.sh).

For the promoter to accept and carry the GitHub provenance, the provenance
policy of the promoter manifest needs the signer and the builder that GitHub
puts into it. Both are the reusable workflow, not the calling `build.yml` or
`helm-chart-package.yaml`, whose path is in
`buildDefinition.externalParameters.workflow` instead:

```yaml
signers:
  - sigstore(identityMatch=regex)::https://token.actions.githubusercontent.com::^https://github\.com/kubernetes-sigs/security-profiles-operator/\.github/workflows/provenance\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$
builders:
  - id: https://github.com/kubernetes-sigs/security-profiles-operator/.github/workflows/provenance.yml
    level: 3
```

Next to the Cloud Build builder of the images, which reaches level 1 only,
the policy verifies at level 1, since any of its signers could claim any of
its builders.

## Staging attestations

The `post-security-profiles-operator-push-image` job builds and signs everything
in the staging registry as the `sp-operator-sa@k8s-staging-images` service
account. Signatures and attestations are Sigstore bundles attached as OCI
referrers, `SIGN=false` skips all of them. The released chart and `spoc` come
from the `post-security-profiles-operator-push-release-artifacts` job, which
signs them as the same account and attaches the provenance of the GitHub
release ("GitHub" below), see [OCI artifacts](#oci-artifacts). The SBOMs of
`spoc` are release assets only.

| Artifact                                           | Signature | Provenance | SBOM | Vulnerability scan, VEX | Build environment, Scorecard |
| -------------------------------------------------- | --------- | ---------- | ---- | ----------------------- | ---------------------------- |
| `security-profiles-operator-{amd64,arm64,ppc64le}` | yes       | yes        | yes  | yes                     | yes                          |
| `security-profiles-operator` (manifest list)       | yes       |            |      |                         |                              |
| `security-profiles-operator` (platform images)     | yes       | yes        | yes  | yes                     | yes                          |
| `security-profiles-operator-bundle`                | yes       | yes        | yes  |                         |                              |
| `security-profiles-operator-catalog`               | yes       | yes        | yes  | yes, of opm             |                              |
| `charts/security-profiles-operator` (`-dev`)       | yes       | yes        | yes  |                         |                              |
| `charts/security-profiles-operator` (releases)     | yes       | GitHub     |      |                         |                              |
| `spoc` (index and platform manifests)              | yes       | GitHub     |      |                         |                              |
| `base/*` and `seccomp-test-profiles`               | yes       | yes        | yes  |                         |                              |

Profiles that are already published are not pushed again, but get
their signature, provenance and SBOM from the next build when the build
identity has not signed or attested them yet, for example because they were
published before the build attested anything
([`hack/attest-artifact.sh`](../hack/attest-artifact.sh)). The build checks for
an existing signature and attestation of each predicate type first, so later
builds add no duplicates, and only signs and attests a published artifact when
it has the content the build would push. A published artifact with other
content, for example a base profile recorded again against the same runtime
version, is left alone with a warning and not verified at the end of the
build, because its tag is taken and the build can't replace it. Publishing the
new content needs a new tag, or, for a base profile that is
not promoted yet, a run with `SKIP_EXISTING=false`, see
[base profiles](release-baseprofiles.md).

The manifest list only carries the signature: verifiers like
nri-supply-chain use the attestations of an index digest instead of the
platform ones as soon as there are any, so partial attestations on the
manifest list would hide the per-arch ones. The platform images it holds are
signed and get the attestations of their per-arch images in the
`security-profiles-operator` repository too, because container runtimes pull
them by digest from there and verifiers and the image promoter look up
signatures and attestations in the repository of the image. The SBOMs keep the
name of the per-arch image.

The attestations are:

- SLSA build provenance (`https://slsa.dev/provenance/v1`), written by
  [`hack/attest-provenance.sh`](../hack/attest-provenance.sh). This section
  documents its build type, the `buildType` of a provenance links to this
  section of the built commit: `externalParameters.source` is the git
  repository and ref with the built commit, `config` the Cloud Build
  configuration and `tag` the image tag. `resolvedDependencies` lists the
  source and what else went into the artifact: the image the binaries are
  built in, the nixpkgs revision and the BuildKit image that builds them for
  the per-arch images, the opm release binary that renders the catalog, the
  opm image it is built on and the bundle for the catalog, the helm release
  archive for the chart, and the `spoc` binary, with the image it was copied
  from, for the profiles.
  `internalParameters` names the Cloud Build project and service account,
  `runDetails.metadata.invocationId` links to the build. The build writes and
  signs the provenance itself, which makes it SLSA Build L1, so
  `runDetails.builder.id` names the Cloud Build configuration of the repository
  and the service account it runs as,
  `https://cloudbuild.googleapis.com/projects/k8s-staging-images/serviceAccounts/sp-operator-sa@k8s-staging-images.iam.gserviceaccount.com/cloudbuild.yaml`.
  The build fails rather than attesting provenance without the service
  account.
- SPDX SBOMs (`https://spdx.dev/Document`). For the images,
  [`hack/attest-sbom.sh`](../hack/attest-sbom.sh) lets bom list the image
  layers, the operating system packages and the Go binary dependencies
  directly from the image, so the SPDX 3 SBOM includes the actual build-time
  module versions. The bundle holds manifests only, so its SBOM lists the image
  and its layers. The catalog is built on the opm image, so its SBOM lists the
  Debian packages of that image and the Go modules of the opm binaries. The
  operator binaries link C libraries like libseccomp and libbpf statically,
  which the image build lists from the nix build inputs in an SPDX 2.3 SBOM at
  `/sbom/native-libraries.spdx.json` of the image
  ([`hack/native-sbom.sh`](../hack/native-sbom.sh)), which is attested as well.
  The SBOMs of the profiles and the chart, written by
  [`hack/attest-artifact.sh`](../hack/attest-artifact.sh) with bom, list what
  the artifact holds: the profile file, or the chart archive and the files in
  it, with their checksums.
- Vulnerability scan (`https://in-toto.io/attestation/vulns/v0.2`) and OpenVEX
  document (`https://openvex.dev/ns`) from govulncheck in binary mode, written
  by [`hack/attest-vulns.sh`](../hack/attest-vulns.sh), for the binaries of the
  per-arch images and for the `opm` and `grpc_health_probe` binaries of the
  catalog. The VEX document marks a vulnerability as affected if one of the
  binaries uses the vulnerable symbols. The opm binaries have no symbol table,
  so for them govulncheck can only tell which vulnerable modules they contain,
  not whether they use the vulnerable code.
  A clean scan has an empty result and no VEX document, because OpenVEX needs at
  least one statement. Affected statements point to the vulnerability entry and
  the fixed version, if there is one. Maintainers assess findings in the
  OpenVEX document, see
  [vulnerability checks and assessments](hacking.md#vulnerability-checks-and-assessments).
  The scan result still lists every finding. The products of a statement are
  the image digest as `pkg:oci` package URL without a repository, which
  matches it wherever it is pulled from, and with the `repository_url` of
  every staging repository it is attested in and of the `registry.k8s.io`
  repository it is promoted to, for VEX consumers that compare qualifiers.
- Build environment (`https://in-toto.io/attestation/build-env/v1`) from the Go
  build information of the binaries, written by
  [`hack/attest-build-env.sh`](../hack/attest-build-env.sh).
- OpenSSF Scorecard result (`https://scorecard.dev/result/v0.1`, a provisional
  predicate type) of this repository from the public Scorecard API, written by
  [`hack/attest-scorecard.sh`](../hack/attest-scorecard.sh). It describes the
  commit Scorecard scanned last, and is skipped with a warning when the API is
  unavailable.

The last step of the build,
[`hack/verify-attestations.sh`](../hack/verify-attestations.sh), verifies every
digest the build pushed, or found published with the content it would push,
against the build identity: the cosign signature
(`https://sigstore.dev/cosign/sign/v1`), and, like the provenance policy of the
image promoter, SLSA provenance about the digest with the builder ID above and
this repository as source, for the per-arch images in both repositories. It
also checks the SBOMs, the vulnerability scan, the VEX document when the scan
found vulnerabilities and the build environment that the table above lists for
the artifact. A missing signature or attestation fails the build. It only
reads from the registry, so it can verify other digests too, see the script.

To verify an attestation by hand, use the predicate type and the signing
identity, for example:

```console
> # Needs cosign v3 or later.
> cosign verify-attestation \
    --type https://slsa.dev/provenance/v1 \
    --certificate-identity sp-operator-sa@k8s-staging-images.iam.gserviceaccount.com \
    --certificate-oidc-issuer https://accounts.google.com \
    us-central1-docker.pkg.dev/k8s-staging-images/sp-operator/security-profiles-operator-amd64:latest
```

### Attestations on registry.k8s.io

The promotion keeps the digests, but `registry.k8s.io` only gets the
attestations of an image when the promoter manifest of the project has a
provenance policy. From kpromo v4.7.0 on, which is not released yet, the image
promoter verifies the staging attestations against such a policy, copies the
ones it accepts next to the promoted digest in `registry.k8s.io`, and can
publish a SLSA verification summary
(`https://slsa.dev/verification_summary/v1`) of its own for it. A policy for
this project, which trusts the attestations of the build identity and checks
the builder ID and source of the provenance like the verification above, is
proposed in [kubernetes/k8s.io#10012](https://github.com/kubernetes/k8s.io/pull/10012)
and not in place yet. It starts in `warn` mode, which reports violations
without blocking the promotion, and `require` mode blocks it.

Until it is, the promoted images only have the `krel-trust` signature of the
promoter on `registry.k8s.io`, and the staging registry is the only place to
verify their attestations, by digest, see
[verifying the released artifacts](verification.md#container-image). Staging
images are deleted after 90 days, and with them their attestations, so do not
advertise SLSA provenance for the promoted images before the policy is in
place. Images promoted before the policy only get their attestations carried
by the repair phase of a promoter run that parses their digests while they are
still in staging, and the production jobs only parse the digests added in the
last 14 days.
