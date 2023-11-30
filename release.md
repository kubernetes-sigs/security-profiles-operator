# Releasing a new version of the security-profiles-operator

A new security-profiles-operator release can be done by overall three Pull Requests (PRs).
Please ensure that no other PRs got merged in between. This can be achieved by
opening a new `Release vx.y.z` issue and applying the `tide/merge-blocker` label
if appropriate.

The overall process should not take longer than a couple of minutes, but it is
required to have one of the repository [owners](./OWNERS) at hand to be able to
merge the PRs.

Run the `./hack/release.sh x.y.z` script by replacing the appropriate version.
The script basically:

- bumps the [`VERSION`](VERSION) file to the target version
- changes the `images` `newName`/`newTag` fields of
  [./deploy/kustomize-deployment/kustomization.yaml](deploy/kustomize-deployment/kustomization.yaml)
  from `gcr.io/k8s-staging-sp-operator/security-profiles-operator` to
  `registry.k8s.io/security-profiles-operator/security-profiles-operator` (`newName`) and the
  corresponding tag (`newTag`).
  has to be run and the changes have to be committed.
- changes the `image` in the `CatalogSource` in the same way at
  [./examples/olm/install-resources.yaml](/examples/olm/install-resources.yaml)
- changes [`hack/ci/e2e-olm.sh`](/hack/ci/e2e-olm.sh) to sed
  `"s#registry.k8s.io/security-profiles-operator/security-profiles-operator-catalog:v0.0.0#${CATALOG_IMG}#g"`
  instead of
  `"s#gcr.io/k8s-staging-sp-operator/security-profiles-operator-catalog:latest#${CATALOG_IMG}#g"`
  (please note to change the version `v0.0.0` to the upcoming release)
- updates [./dependencies.yaml](./dependencies.yaml) `spo-current` version as
  well as its linked files. Run `make verify-dependencies` to verify the
  results.
- updates ./hack/deploy-localhost.patch to match the new deployment
- updates [./deploy/base/clusterserviceversion.yaml](./deploy/base/clusterserviceversion.yaml)
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
`amd64` and `arm`).

We can use the tool
[`kpromo`](https://github.com/kubernetes-sigs/promo-tools#kpromo) to allow
easier retrieval and modification of the necessary container image digests.
To run the tool from `$GOPATH/src/sigs.k8s.io/promo-tools`, just execute:

```bash
> export GITHUB_TOKEN=<YOUR_TOKEN>
> kpromo pr \
    --fork <YOUR_GH_USERNAME> \
    --project sp-operator \
    --tag v0.x.y
```

This will automatically create a PR in the k/k8s.io repository. If this PR got
merged, then we're finally ready to [create the
release](https://github.com/kubernetes-sigs/security-profiles-operator/releases/new)
directly on GitHub and add the release notes. The release notes can be generated
by the [official Kubernetes Release Notes
tool](https://github.com/kubernetes/release/tree/master/cmd/release-notes).

Run `make nix-spoc` and attach the results from the `build` directory to the
GitHub release.

After that, another PR against this repository has to be created, which:

- bumps the [`VERSION`](VERSION) file to the next minor version, but now including the
  suffix `-dev`, for example `1.0.0-dev`.
- changes the `images` `newName`/`newTag` fields in
  [./deploy/kustomize-deployment/kustomization.yaml](deploy/kustomize-deployment/kustomization.yaml)
  back to `gcr.io/k8s-staging-sp-operator/security-profiles-operator`
  (`newName`) and `latest` (`newTag`) and runc `make bundle`
- changes the tag in the same way in the OLM example manifest at
  [./examples/olm/install-resources.yaml](/examples/olm/install-resources.yaml)
- reverts the changes to [`hack/ci/e2e-olm.sh`](/hack/ci/e2e-olm.sh)
- reverts the changes to [`deploy/helm/Chart.yaml`](/deploy/helm/Chart.yaml)
- reverts the changes to [`hack/deploy-localhost.patch`](/hack/deploy-localhost.patch)
- reverts the changes to [`test/e2e_test.go`](/test/e2e_test.go)
- updates [./dependencies.yaml](./dependencies.yaml) `spo-current` version as
  well as its linked files. Run `make verify-dependencies` to verify the
  results.

Create a new pull request in the OperatorHub.io [community
operators](https://github.com/k8s-operatorhub/community-operators) repository to
add the new version like in [this
PR](https://github.com/k8s-operatorhub/community-operators/pull/1672).

The last step about the release creation is to send a release announcement to
the [#security-profiles-operator Slack channel](https://kubernetes.slack.com/messages/security-profiles-operator).
