# Releasing a new version of the security-profiles-operator

A new security-profiles-operator release can be done by overall three Pull Requests (PRs).
Please ensure that no other PRs got merged in between. The overall process
should not take longer than a couple of minutes, but it is required to have one
of the repository [owners](./OWNERS) at hand to be able to merge the PRs.

The first PR targets this repository and:

- bumps the [`VERSION`](VERSION) file to the target version
- changes the `images` `newName`/`newTag` fields of
  [./deploy/base/kustomization.yaml](deploy/base/kustomization.yaml) from
  `gcr.io/k8s-staging-sp-operator/security-profiles-operator` to
  `k8s.gcr.io/sp-operator/security-profiles-operator` (`newName`) and the
  corresponding tag (`newTag`). After that the make target `make deployments`
  has to be run and the changes have to be committed. This requires
  [kustomize](https://github.com/kubernetes-sigs/kustomize) to be available on
  the host system.

After this PR has been merged, we have to watch out the successful build of the
container image via the automatically triggered
`post-security-profiles-operator-push-image` post submit job in prow. All jobs of this
type can be found either on the commit status on the master branch or [in prow
directly](https://prow.k8s.io/?job=post-security-profiles-operator-push-image).

If the image got built successfully, then we can create a second PR to [the
k8s.io GitHub repository](https://github.com/kubernetes/k8s.io). This PR
promotes the built container image by:

- adding an entry to the `dmap` of the file
  `k8s.gcr.io/images/k8s-staging-sp-operator/images.yaml`:
  ```
  "sha256:3c2fa3e061d27379536aae697bec20ef08637590bad7b19b00038c7788b08a7a": ["v1.0.0"]
  ```

The version (`v1.0.0` in this example) has to match the changed version in the
deployment manifest of the first PR. The `sha256` value can be retrieved by
multiple tools, for example by using [skopeo](https://github.com/containers/skopeo):

```
> skopeo inspect docker://gcr.io/k8s-staging-sp-operator/security-profiles-operator:latest | jq -r .Digest
sha256:3c2fa3e061d27379536aae697bec20ef08637590bad7b19b00038c7788b08a7a
```

If this PR got merged, then we're finally ready to [create the
release](https://github.com/kubernetes-sigs/security-profiles-operator/releases/new)
directly on GitHub and add the release notes. The release notes can be generated
by the [official Kubernetes Release Notes
tool](https://github.com/kubernetes/release/tree/master/cmd/release-notes).

After that, another PR against this repository has to be created, which:

- bumps the [`VERSION`](VERSION) file to the next minor version, but now including the
  suffix `-dev`, for example `1.0.0-dev`.
- changes the `images` `newName`/`newTag` fields in
  [./deploy/base/kustomization.yaml](deploy/base/kustomization.yaml) back to
  `gcr.io/k8s-staging-sp-operator/security-profiles-operator` (`newName`) and `latest`
  (`newTag`).

The last step about the release creation is to send a release announcement to
the [#security-profiles-operator Slack channel](https://kubernetes.slack.com/messages/security-profiles-operator).
