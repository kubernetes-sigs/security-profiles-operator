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

If the image got built successfully, then we can create a second PR to [the
k8s.io GitHub repository](https://github.com/kubernetes/k8s.io). This PR
promotes the built container images (the manifest as well as the builds for
`amd64`, `arm64` and `ppc64le`).

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

This will automatically create a PR in the k/k8s.io repository. The second
`--tag` picks up the helm chart, which the staging build pushes as
`us-central1-docker.pkg.dev/k8s-staging-images/sp-operator/charts/security-profiles-operator` with the
version without the `v` prefix.

The promotion copies the images by digest, but not their attestations, see
[staging attestations](#staging-attestations). Once the promotion PR is
merged, check that the attestations still apply to what users install: the
per-architecture images on `registry.k8s.io` have to have the digests the
staging build attested, which the commands in
[verification.md](verification.md#container-image) verify for a release.

If this PR got merged, tag the release. Tags created in the GitHub UI are
lightweight and unsigned, so check out the merged commit of the first PR and
run [`hack/tag-release.sh`](../hack/tag-release.sh). It creates the signed,
annotated tag `vx.y.z` for the version in the [`VERSION`](../VERSION) file,
which needs a git signing key (`user.signingkey`, GPG or SSH with
`gpg.format=ssh`), and verifies it with `git verify-tag`. It refuses to tag a
development version, a dirty tree or an existing tag, and pushes nothing.
Check the signature once more and push the tag:

```console
> git verify-tag vx.y.z
> git push origin vx.y.z
```

Set `REMOTE` for the script to print the push command with another remote.
The `v*` tags should be protected in the repository settings (a tag ruleset
which restricts their creation, update and deletion to the release managers),
since the release workflows trust a tag to be a reviewed release commit.

Then we're finally ready to [create the
release](https://github.com/kubernetes-sigs/security-profiles-operator/releases/new)
on GitHub from the pushed tag and add the release notes. The changelog is auto-generated
based on PR labels and the configuration in
[`.github/release.yml`](../.github/release.yml). The introduction above it is
written by hand, start from
[`.github/release-notes-template.md`](../.github/release-notes-template.md) and
replace the version. The verification commands live in
[`verification.md`](verification.md), so the release only links them and they
stay correct for all releases.

Publishing the release triggers the [`build`](../.github/workflows/build.yml)
workflow, which attaches the `spoc` binaries for all architectures and the
`spoc.spdx.json` and `spoc-native.spdx.json` SBOMs with their signatures
(`*.sigstore.json`), checksums and SLSA build provenance (`spoc.intoto.jsonl`)
to the release. Its `spoc / reproducible` job checks that the released
`spoc.amd64` is bit for bit the `spoc` of the promoted image of the release. The
[`helm-chart-package`](../.github/workflows/helm-chart-package.yaml) workflow
attaches the chart archive with its signature and provenance. Nothing has to
be built or uploaded by hand, `make nix-spoc` is only meant for local builds.
Verify that the files are present. The reusable
[`provenance`](../.github/workflows/provenance.yml) workflow creates the
provenance of both workflows, see
[SLSA build levels](verification.md#slsa-build-levels).

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

## Staging attestations

The `post-security-profiles-operator-push-image` job builds and signs everything
in the staging registry as the `sp-operator-sa@k8s-staging-images` service
account. Signatures and attestations are Sigstore bundles attached as OCI
referrers, `SIGN=false` skips all of them.

| Artifact                                           | Signature | Provenance | SBOM, vulnerability scan, VEX, build environment |
| -------------------------------------------------- | --------- | ---------- | ------------------------------------------------ |
| `security-profiles-operator-{amd64,arm64,ppc64le}` | yes       | yes        | yes, plus the Scorecard result                   |
| `security-profiles-operator` (manifest list)       | yes       |            |                                                  |
| `security-profiles-operator` (platform images)     | yes       | yes        | yes, plus the Scorecard result                   |
| `security-profiles-operator-{bundle,catalog}`      | yes       | yes        |                                                  |
| `charts/security-profiles-operator`                | yes       | yes        |                                                  |
| `base/*` and `seccomp-test-profiles`               | yes       | yes        |                                                  |

Provenance is only attested when an artifact gets pushed, so profiles that were
already published don't get provenance from later builds. If the check for an
existing version fails, the build pushes the identical content again, which
keeps its digest and gets a second provenance attestation from that build. Profiles, the bundle,
the catalog and the chart contain no software packages, which is why they have
no SBOM, vulnerability scan or VEX document. The manifest list only carries
the signature: verifiers like nri-supply-chain use the attestations of an index
digest instead of the platform ones as soon as there are any, so partial
attestations on the manifest list would hide the per-arch ones. The platform
images it holds are signed and get the attestations of their per-arch images
in the `security-profiles-operator` repository too, because container runtimes
pull them by digest from there and verifiers and the image promoter look up
signatures and attestations in the repository of the image. The VEX documents
name the image in both repositories, the SBOMs keep the name of the per-arch
image.

The attestations are:

- SLSA build provenance (`https://slsa.dev/provenance/v1`), written by
  [`hack/attest-provenance.sh`](../hack/attest-provenance.sh). This section
  documents its build type, the `buildType` of a provenance links to this
  section of the built commit: `externalParameters.source` is the git
  repository and ref with the built commit, `config` the Cloud Build
  configuration and `tag` the image tag. `resolvedDependencies` lists the
  source, the image the binaries are built in and the nixpkgs revision, for
  the per-architecture images also the BuildKit image that builds them.
  `internalParameters` names the Cloud Build project and service account,
  `runDetails.metadata.invocationId` links to the build. The build writes and
  signs the provenance itself, which makes it SLSA Build L1, so
  `runDetails.builder.id` names the Cloud Build configuration of the repository
  and the service account it runs as,
  `https://cloudbuild.googleapis.com/projects/k8s-staging-images/serviceAccounts/sp-operator-sa@k8s-staging-images.iam.gserviceaccount.com/cloudbuild.yaml`.
- SPDX SBOMs (`https://spdx.dev/Document`), written by
  [`hack/attest-sbom.sh`](../hack/attest-sbom.sh). bom extracts the Go binary
  dependencies directly from the image, so the SPDX 3 SBOM includes the actual
  build-time module versions. The binaries link C libraries like libseccomp
  and libbpf statically, which the image build lists from the nix build inputs
  in an SPDX 2.3 SBOM at `/sbom/native-libraries.spdx.json` of the image
  ([`hack/native-sbom.sh`](../hack/native-sbom.sh)), which is attested as well.
- Vulnerability scan (`https://in-toto.io/attestation/vulns/v0.2`) and OpenVEX
  document (`https://openvex.dev/ns`) from govulncheck in binary mode, written
  by [`hack/attest-vulns.sh`](../hack/attest-vulns.sh). The VEX document marks a
  vulnerability as affected if one of the binaries uses the vulnerable symbols.
  A clean scan has an empty result and no VEX document, because OpenVEX needs at
  least one statement. Affected statements point to the vulnerability entry and
  the fixed version, if there is one. Maintainers assess findings in the
  OpenVEX document, see
  [vulnerability checks and assessments](hacking.md#vulnerability-checks-and-assessments).
  The scan result still lists every finding.
- Build environment (`https://in-toto.io/attestation/build-env/v1`) from the Go
  build information of the binaries, written by
  [`hack/attest-build-env.sh`](../hack/attest-build-env.sh).
- OpenSSF Scorecard result (`https://scorecard.dev/result/v0.1`, a provisional
  predicate type) of this repository from the public Scorecard API, written by
  [`hack/attest-scorecard.sh`](../hack/attest-scorecard.sh). It describes the
  commit Scorecard scanned last, and is skipped with a warning when the API is
  unavailable.

To verify them, use the predicate type and the signing identity, for example:

```console
> # Needs cosign v3 or later.
> cosign verify-attestation \
    --type https://slsa.dev/provenance/v1 \
    --certificate-identity sp-operator-sa@k8s-staging-images.iam.gserviceaccount.com \
    --certificate-oidc-issuer https://accounts.google.com \
    us-central1-docker.pkg.dev/k8s-staging-images/sp-operator/security-profiles-operator-amd64:latest
```

The attestations stay in the staging registry, the image promotion does not copy
them to `registry.k8s.io` yet.

This is the single largest gap in the supply chain story: everything above is
produced for the staging images, while users install from `registry.k8s.io`,
where only the krel signature is present. Until the referrers are promoted,
do not advertise SLSA provenance for the promoted images. Closing it needs
either the image promoter to copy the OCI referrers alongside the manifest, or
a post promotion workflow that re-attests the promoted digest from a job that
can prove it observed the promotion. Both require a change outside this
repository, in kubernetes/k8s.io.
