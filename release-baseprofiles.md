# Base profiles

[Installation and Usage](installation-usage.md) | [Installation](installation.md) | [Profiles](profiles.md) | [CLI](cli.md) | [Metrics](metrics.md) | [Troubleshooting](troubleshooting.md)

<!-- toc -->
- [Where they live](#where-they-live)
- [How a profile is recorded](#how-a-profile-is-recorded)
- [Updating a profile](#updating-a-profile)
- [Publishing by hand](#publishing-by-hand)
- [Promoting to registry.k8s.io](#promoting-to-registryk8sio)
- [Verifying](#verifying)
<!-- /toc -->

The operator ships seccomp profiles recorded against the container runtimes it
supports, `runc` and `crun`. They serve as the base for profiles that a
workload builds on, either through the `baseProfileName` field of a
`SeccompProfile` or, for a container runtime implementing
[KEP-6061](https://github.com/kubernetes/enhancements/issues/6061), as a
`type: OCI` seccomp profile.

## Where they live

Each runtime has its own artifact, with the runtime version the profile was
recorded against as the tag:

| Location | Purpose |
| - | - |
| `gcr.io/k8s-staging-sp-operator/base/<runtime>:<version>` | published on merge, anonymously readable, what the end-to-end tests read on `main` |
| `gcr.io/k8s-staging-sp-operator/base/<runtime>:latest` | follows the newest recording, for manual pulls; staging only, never promoted |
| `registry.k8s.io/security-profiles-operator/base/<runtime>:<version>` | promoted from staging, what a cluster should reference and what the end-to-end tests read on a release branch |

They are published in the runtime format: a single layer holding the profile as
OCI runtime-spec JSON, identified by the media type
`application/vnd.cncf.seccomp-profile.config.v1+json`. Container runtimes
consume that format directly, and the operator recognizes it by media type when
resolving an `oci://` base profile, so one artifact serves both. The profile
object is named after the last path segment, so `base/runc` is pulled as a
`SeccompProfile` called `runc`.

## How a profile is recorded

The `e2e-seccomp-profile` job records the profiles rather than a person doing
it. It boots a virtual machine, runs a workload under the profile recorder for
each runtime, writes the recorded syscalls into
`examples/baseprofile-<runtime>.yaml`, and sets `metadata.name` to
`<runtime>-v<version>` from the runtime installed in the machine.

The job then diffs the working tree and fails if anything changed, ignoring
syscalls known to appear at random. A failure is the signal that a profile is
due for an update, and it is expected whenever the container runtime packages
in the job change. The job log shows which syscalls came and went, and the
regenerated files are attached to the run as the `recorded-base-profiles`
artifact.

## Updating a profile

Commit the regenerated `examples/baseprofile-<runtime>.yaml`, either from the
uploaded artifact or by rerunning the recording locally. Nothing else in the
repository has to change:

- the end-to-end test that applies the profile reads `metadata.name` from the
  file
- the end-to-end test that pulls the artifact derives the tag from that name

Merging publishes it: the staging build pushes the new version (and repoints
`latest`), so the next test run exercises the new recording. Promote the new
version before cutting a release, because `hack/release.sh` points the test at
`registry.k8s.io`.

## Publishing by hand

The staging build publishes on merge, so this is only needed to bootstrap a new
registry or when the build cannot run:

```console
> USERNAME=<user> PASSWORD=<token> make push-base-profiles
```

`REGISTRY` selects where to publish, `SIGN=false` skips signing for
environments without an OIDC identity, and `SKIP_EXISTING=false` republishes a
version that is already there.

Versions that are already published are skipped. Identical content yields the
same digest (the manifest's creation timestamp is fixed unless
`SOURCE_DATE_EPOCH` is set), so a republish would be a no-op for the registry;
skipping only avoids the pushes and the `latest` repoint. Skipping is keyed on
the version tag, so a profile that is re-recorded without the runtime version
changing needs `SKIP_EXISTING=false` to reach the registry.

## Promoting to registry.k8s.io

Staging is where the tests read from, `registry.k8s.io` is where clusters read
from, and content moves between them through a promotion pull request against
[kubernetes/k8s.io](https://github.com/kubernetes/k8s.io):

```console
> kpromo pr --project sp-operator --image base/<runtime> --tag <version>
```

Promote the versioned tag only. Tags in `registry.k8s.io` cannot be repointed,
so a promoted `latest` would be frozen at whatever it pointed to first, and
content re-recorded under a version that was already promoted needs a new tag.

`kpromo` cannot sign its commit, so it fails with `invalid checksum` when
`commit.gpgsign` is set. Run it with a `GIT_CONFIG_GLOBAL` that turns signing
off.

## Verifying

Both registries are anonymously readable:

```console
> spoc pull -o /tmp/profile.json registry.k8s.io/security-profiles-operator/base/<runtime>:<version>
> curl -fsSL -H 'Accept: application/vnd.oci.image.manifest.v1+json' \
    https://gcr.io/v2/k8s-staging-sp-operator/base/<runtime>/manifests/latest
```

Artifacts published by the staging build are unsigned, since it has no OIDC
identity, so verification has to be skipped for those with `spoc pull -s`.
