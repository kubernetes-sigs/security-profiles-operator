[Documentation](README.md) | [Installation](installation.md) | [Profiles](profiles.md) | **CLI** | [Metrics](metrics.md) | [Troubleshooting](troubleshooting.md)

<!-- toc -->
- [Command Line Interface (CLI)](#command-line-interface-cli)
  - [Record seccomp profiles for a command](#record-seccomp-profiles-for-a-command)
  - [Run commands with seccomp profiles](#run-commands-with-seccomp-profiles)
  - [Merge security profiles](#merge-security-profiles)
  - [Convert profiles to their raw format](#convert-profiles-to-their-raw-format)
  - [Install and remove AppArmor profiles](#install-and-remove-apparmor-profiles)
  - [Pull security profiles from OCI registries](#pull-security-profiles-from-oci-registries)
  - [Push security profiles to OCI registries](#push-security-profiles-to-oci-registries)
  - [Pushing profiles for container runtimes](#pushing-profiles-for-container-runtimes)
    - [Publishing base profiles](#publishing-base-profiles)
  - [Using multiple platforms](#using-multiple-platforms)
<!-- /toc -->

## Command Line Interface (CLI)

The Security Profiles Operator CLI `spoc` aims to support use cases where
Kubernetes is not available at all (for example in edge scenarios). It targets
to provide re-used functionality from the operator itself, especially for
development and testing environments. In the future, we plan to extend the CLI
to interact with the operator itself.

For now, the CLI is able to:

- Record seccomp and AppArmor profiles for a command in YAML (CRD) and raw
  format.
- Run commands with applied seccomp profiles in both formats.
- Merge multiple security profiles into a combined one.
- Convert seccomp and AppArmor profile CRDs to their raw format.
- Install and remove AppArmor profiles on the local machine.
- Push security profiles to and pull them from OCI registries.

Every command, flag and environment variable of `spoc` is listed in the
generated [command line reference](reference/spoc.md).

`spoc` can be retrieved either by downloading the statically linked binary
directly from the [available releases][releases], which also publish it as
OCI artifact `registry.k8s.io/security-profiles-operator/spoc` (see
[verification](verification.md#oci-artifacts-on-registryk8sio)), or by
running it within the official container images:

```console
> podman run -it registry.k8s.io/security-profiles-operator/security-profiles-operator:v1.1.1 spoc
NAME:
   spoc - Security Profiles Operator CLI

USAGE:
   spoc [global options] command [command options]

VERSION:
   v1.1.1

COMMANDS:
   version, v  display detailed version information
   record, r   run a command and record the security profile
   merge, m    merge multiple security profiles
   convert, c  convert a security profile to its raw format
   install, i  install a security profile on the local machine
   remove, rm  remove a security profile from the local machine
   run, x      run a command using a security profile
   push, p     push a profile to a container registry
   pull, l     pull a profile from a container registry
   help, h     Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --help, -h     show help
   --version, -v  print the version
```

v1.1.0 and older releases don't publish the OCI artifact, see
[older releases](verification.md#older-releases).

Every command documents its flags via `spoc <command> --help`. `spoc version`
prints detailed version information, and `spoc version --json` / `-j` prints it
as JSON.

The released binaries are signed and have SLSA build provenance. See
[verifying the released artifacts](verification.md#command-line-binaries) for
the commands.

[releases]: https://github.com/kubernetes-sigs/security-profiles-operator/releases/latest

### Record seccomp profiles for a command

To record a seccomp profile via `spoc`, run the corresponding subcommand
followed by any command and arguments:

```console
> sudo spoc record echo test
10:09:09.182417 Loading bpf module...
…
10:09:13.551802 Adding base syscalls: capget, capset, chdir, …
10:09:13.552218 Wrote profile to: profile.yaml
```

Now the seccomp profile should be written in the CRD format:

```console
> cat profile.yaml
```

```yaml
apiVersion: security-profiles-operator.x-k8s.io/v1
kind: SeccompProfile
metadata:
  name: echo
spec:
  architectures:
    - SCMP_ARCH_X86_64
  defaultAction: SCMP_ACT_ERRNO
  syscalls:
    - action: SCMP_ACT_ALLOW
      names:
        - access
        - …
        - write
```

The output file path can be specified as well by using `spoc record
-o/--output-file`.

We can see that `spoc` automatically adds required base syscalls for OCI
container runtimes to ensure compatibility with them to allow using the profile
within Kubernetes. This behavior can be disabled by using `spoc record
-n/--no-base-syscalls`, or by specifying custom syscalls via `spoc record
-b/--base-syscalls`.

It is also possible to change the format to JSON via `spoc record -t/--type
raw-seccomp`. The other supported types are `apparmor`, `raw-apparmor` and
`all`:

```console
> sudo spoc record -t raw-seccomp echo test
…
10:15:17.309114 Wrote profile to: profile.json
```

```console
> jq . profile.json
```

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    {
      "names": ["access", "…", "write"],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

All commands are interruptible by using Ctrl^C, while `spoc record` will still
write the resulting seccomp profile after process terminating.

`spoc record` drops the privileges of `sudo` when starting the command, so
that the command runs as the user who invoked `sudo`. Use `--privileged` to
run the command with the privileges of `spoc` instead. With `--no-proc-start`,
`spoc record` does not start a command at all, but records all processes
matching the command name until it gets interrupted by Ctrl^C or `SIGINT`. This
is useful for processes which are started by another tool, like a service
manager:

```console
> sudo spoc record --no-proc-start my-daemon
```

### Run commands with seccomp profiles

If we now want to test the resulting profile, then `spoc` is able to run any
command by using seccomp profiles via `spoc run`:

```console
> sudo spoc run -p profile.json echo test
2023/03/10 10:20:00 Reading file profile.json
2023/03/10 10:20:00 Setting up seccomp
2023/03/10 10:20:00 Running command with PID: 567625
test
```

If we now modify the profile, for example by forbidding `chmod`:

```console
> jq 'del(.syscalls[0].names[] | select(. | contains("chmod")))' profile.json > profile-chmod.json
```

`spoc run` reads raw JSON profiles if the file name ends with `.json`, and
`SeccompProfile` CRDs in YAML otherwise. Other kinds and profiles with a
`baseProfileName` are rejected, because the syscalls of the base profile would
be missing. The `--type` / `-t` flag selects the profile type, which is
`seccomp`, the only supported type for now. The profile is loaded in the
process of the command right before it gets executed, so `spoc` itself is not
confined. `SIGINT`, `SIGTERM` and `SIGHUP` are forwarded to the command, and
`spoc run` exits with the exit code of the command.

Then running `chmod` via `spoc run` will now throw an error, because the syscall
is not allowed any more:

```console
> sudo spoc run -p profile-chmod.json chmod +x profile-chmod.json
10:25:38.020716 Reading file profile-chmod.json
10:25:38.021093 Setting up seccomp
10:25:38.023481 Running command with PID: 594242
chmod: changing permissions of 'profile-chmod.json': Operation not permitted
10:25:38.025217 Command failed: wait for command: exit status 1
```

### Merge security profiles

`spoc merge` combines multiple seccomp, SELinux or AppArmor profile CRDs of the
same kind into one profile. Permissions are additive, and for AppArmor the
first profile may additionally contain glob paths:

```console
> spoc merge -o /tmp/merged.yaml /tmp/profile-a.yaml /tmp/profile-b.yaml
```

The output defaults to `profile.yaml`. With `--check` / `-c`, no output
file is written. Instead, `spoc merge` exits with code `1` if the first profile
is not a superset of all others, which is useful to check whether a base
profile is up to date. Other failures, like an unreadable input file, exit with
code `1` as well. The log tells both apart: an outdated base profile logs
`Base profile needs an update.`, a failure logs `Unable to run: …`.

### Convert profiles to their raw format

`spoc convert` turns a `SeccompProfile` CRD into a raw OCI runtime-spec seccomp
profile in JSON, and an `AppArmorProfile` CRD into a raw AppArmor profile. The
result is written to stdout unless `--output-file` / `-o` is set:

```console
> spoc convert -o profile.json profile.yaml
```

Fields which are specific to the operator, like the base profile name and the
listener fields, are dropped from seccomp profiles. For AppArmor,
`--program-name` / `-p` sets the path of the confined program. Without it, an
unattached profile named after the CRD is created.

### Install and remove AppArmor profiles

`spoc install` loads an `AppArmorProfile` CRD into the kernel of the local
machine, and `spoc remove` unloads it again. Both take the profile file
(default `profile.yaml`) and optionally the path of the executable which
should be confined, which is used as the profile name:

```console
> sudo spoc install profile.yaml /usr/bin/my-app
> sudo spoc remove profile.yaml /usr/bin/my-app
```

### Pull security profiles from OCI registries

The `spoc` client is able to pull security profiles from OCI artifact compatible
registries. To do that, just run `spoc pull`, here for a
[base profile](release-baseprofiles.md). Replace `<version>` with one of the
tags that `crane ls registry.k8s.io/security-profiles-operator/base/runc`
lists:

```console
> spoc pull registry.k8s.io/security-profiles-operator/base/runc:<version>
16:32:29.795597 Pulling profile from: registry.k8s.io/security-profiles-operator/base/runc:<version>
16:32:29.795610 Resolving digest of image (image=registry.k8s.io/security-profiles-operator/base/runc:<version>)
16:32:30.106241 Verifying signature (identityRegexp=…, oidcIssuerRegexp=^https://accounts\.google\.com$, …)
16:32:31.570335 Verified signature (digest=sha256:…, signature=sha256:…, legacy=true)
16:32:33.208695 Creating file store (dir=/tmp/pull-3199397214)
16:32:33.208743 Copying profile from repository
16:32:33.208751 Source image (image=registry.k8s.io/security-profiles-operator/base/runc@sha256:…)
16:32:34.119652 Checking profile contents
16:32:34.119677 Reading profile layer (title=profile.json, runtimeFormat=true)
16:32:34.120114 Got SeccompProfile: runc
16:32:34.120119 Saving profile in: profile.json
```

The profile can be now found in `profile.yaml` in the current directory or the
specified output file `--output-file` / `-o`. Profiles are written with the
permissions `0644`. If username and password authentication is required, either
use the `--username`, `-u` flag or export the `SPOC_USERNAME` environment
variable. To set the password, export the `SPOC_PASSWORD` environment variable
or pass it on stdin with `--password-stdin`. Giving only one of both is an
error. Without any of them, the credentials of the docker config (for example
from `docker login`) are used. The former `USERNAME` and `PASSWORD` environment
variables still work, but print a deprecation warning.

`spoc pull` verifies the signature of the artifact. The signer can be
restricted with `--allowed-identity-regexp` / `-i` (or the
`ALLOWED_IDENTITIES_REGEXP` environment variable) and
`--allowed-oidc-issuer-regexp` (or `ALLOWED_OIDC_ISSUER_REGEXP`), see
[verifying the released artifacts](verification.md) for the values of the
official profiles. The verification can be disabled with
`--disable-signature-verification` / `-s` (or
`DISABLE_SIGNATURE_VERIFICATION`).

The following flags pin the signer more strictly or verify without the public
Sigstore infrastructure:

- `--certificate-identity` (or `SPOC_CERTIFICATE_IDENTITY`) and
  `--certificate-oidc-issuer` (or `SPOC_CERTIFICATE_OIDC_ISSUER`) require the
  exact identity and OIDC issuer of the keyless signature certificate. They
  take precedence over the corresponding regexp flags.
- `--key` / `-k` (or `SPOC_KEY`) verifies a signature made with a key pair
  instead of a keyless certificate. It accepts the path of a PEM encoded public
  key, like the `cosign.pub` of `cosign generate-key-pair`. The identity and
  issuer flags do not apply to key signatures.
- `--trusted-root` (or `SPOC_TRUSTED_ROOT`) verifies against a Sigstore trusted
  root JSON file instead of the one distributed through TUF, for private
  Sigstore deployments and air-gapped environments.
- `--offline` (or `SPOC_OFFLINE`) verifies with the trusted root cached from
  TUF as long as it has not expired instead of refreshing it. The transparency
  log entry bundled with the signature is verified in any case, it is never
  looked up online. With an empty cache, pass `--trusted-root` or run
  `spoc pull` once without `--offline` to populate it.

The official repositories are verified against the official signers as long
as the identity and issuer regexps are left at their default `.*` and `--key`
is not set. `--certificate-identity` alone replaces only the official
identity and `--certificate-oidc-issuer` alone only the official issuer, the
other one stays pinned to the official signers. The explicit flags apply to
official repositories as well, and a notice is logged then, because official
artifacts are signed keyless by the official signers through the public
Sigstore instance. A warning is logged whenever the verification accepts any
identity or any issuer, because a signature then only proves that somebody
signed the artifact, not somebody trusted.

### Push security profiles to OCI registries

The `spoc` client is also able to push security profiles from OCI artifact
compatible registries. To do that, just run `spoc push`:

```
> export SPOC_USERNAME=my-user
> export SPOC_PASSWORD=my-pass
> spoc push -f ./examples/baseprofile-crun.yaml registry.example.com/profiles/crun:v1.8.1
16:35:43.899886 Pushing profiles to: registry.example.com/profiles/crun:v1.8.1
16:35:43.899939 Creating file store (dir=/tmp/push-3618165827)
16:35:43.899943 Reading profiles (count=1)
16:35:43.899947 Adding profile to store (file=/home/user/examples/baseprofile-crun.yaml, platform=)
16:35:43.900061 Packing files (mediaType=application/vnd.unknown.config.v1+json)
16:35:43.900282 Verifying reference (ref=registry.example.com/profiles/crun:v1.8.1)
16:35:43.900310 Using tag (tag=v1.8.1)
16:35:43.900313 Creating repository (ref=registry.example.com/profiles/crun)
16:35:43.900319 Using username and password
16:35:43.900321 Copying profile to repository
16:35:46.975916 Pushed artifact (reference=registry.example.com/profiles/crun@sha256:…)
16:35:46.976108 Signing OCI artifact (digest=sha256:…)

        The sigstore service, hosted by sigstore a Series of LF Projects, LLC, is provided pursuant to …
        Note that if your submission includes personal data associated with this signed artifact, it will be part of an immutable record.
        …
Your browser will now be opened to:
https://oauth2.sigstore.dev/auth/auth?access_type=…
…
```

We can specify a username and password in the same way as for `spoc pull`.
Artifacts are signed on push and verified on pull by default. The signature
is a Sigstore bundle that is attached to the pushed digest through the OCI
referrers API, or the referrers tag schema on registries without it, in the
format `cosign sign` writes, so `cosign verify` can verify it. On pull, bundles
are verified if the artifact has any, otherwise the legacy cosign signature
tags of artifacts pushed by older `spoc` versions or by the image promoter of
registry.k8s.io are verified. Keyless signing needs an OIDC identity token.
`spoc push` takes it from the environment if there is one: GitHub Actions
(`ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN`), the
`SIGSTORE_ID_TOKEN` environment variable, a token file at
`/var/run/sigstore/cosign/oidc-token` or the service account of the Google
Compute Engine metadata server, as used by Cloud Build. Otherwise it signs in
to the Sigstore OIDC provider in the browser, or with the device flow if there
is no terminal. Build systems and test environments do not necessarily have
an identity, so `--disable-signing` / `-s` skips signing. Consumers of an
unsigned artifact have to skip verification as well, by using `spoc pull
--disable-signature-verification` / `-s` or by exporting
`DISABLE_SIGNATURE_VERIFICATION=true`. The identities and OIDC issuers accepted
during verification can be restricted with `--allowed-identity-regexp` / `-i`
and `--allowed-oidc-issuer-regexp`. It is possible to add custom
annotations to the artifact manifest by using the `--annotations` / `-a` flag
multiple times in `KEY:VALUE` format; only the first colon separates the key
from the value, so timestamps keep theirs. The layers only carry their
`org.opencontainers.image.title` annotation.

The manifest's `org.opencontainers.image.created` annotation is fixed to
`1970-01-01T00:00:00Z` unless it is set explicitly with `--annotations` or
`SOURCE_DATE_EPOCH` is exported (seconds since the epoch, the reproducible
builds convention). The layers of a multi-platform artifact are ordered by
their name. Pushing identical content again therefore yields the same digest
instead of a new, untagged manifest.

`spoc pull` refuses to fetch any artifact blob larger than 16 MiB, so a
registry cannot make the client read arbitrary amounts of data. The
credentials given via `--username` and `$SPOC_PASSWORD` are used for the registry
access of the signature as well, both when signing on push and when verifying
on pull.

`--plain-http` on `spoc push` and `spoc pull` reaches the registry over HTTP
instead of HTTPS, for local registries in tests and other registries without
TLS.

### Pushing profiles for container runtimes

Container runtimes consume seccomp profiles from OCI artifacts in the format
defined by [KEP-6061](https://github.com/kubernetes/enhancements/issues/6061):
exactly one layer containing the profile as OCI runtime-spec JSON, identified
by the media type `application/vnd.cncf.seccomp-profile.config.v1+json`. This
differs from the profile CRD artifacts above, which keep the generic
`application/vnd.unknown.config.v1+json` artifact type together with the empty
OCI config descriptor. The operator accepts either as an `oci://` base
profile.

The profiles the Kubernetes end-to-end tests for KEP-6061 consume are pushed
from this repository by `make push-test-artifacts`. The staging build pushes
them to `us-central1-docker.pkg.dev/k8s-staging-images/sp-operator/seccomp-test-profiles`
and attests them, and they are promoted to
`registry.k8s.io/security-profiles-operator/seccomp-test-profiles`. The
digests that were promoted before the build attested them have no
attestations: their staging tags point to digests that were pushed again with
another manifest, and only those get attested, see
[staging attestations](release.md#staging-attestations).

The recorded base profiles are published by `make push-base-profiles` in the
runtime format, one artifact per runtime with the recorded runtime version as
the tag. Container runtimes consume them for `type: OCI` profiles, and the
operator reads the same artifacts for `oci://` base profiles because it
recognizes the format by media type, so one artifact serves both.

The staging build publishes them to
`us-central1-docker.pkg.dev/k8s-staging-images/sp-operator/base/<runtime>:<version>`, which is where the
end-to-end tests read them from, and they are promoted to
`registry.k8s.io/security-profiles-operator/base/<runtime>:<version>`, which is
what to reference from a cluster. The profile object keeps the name of the last
path segment, so an artifact at `base/runc` is pulled as a `SeccompProfile`
called `runc`.

Promotion pins a digest per tag and tags in `registry.k8s.io` can never be
repointed, so a profile re-recorded against the same runtime version needs a
new tag.

#### Publishing base profiles

The recorded base profiles are published by `make push-base-profiles`, one
artifact per runtime with the recorded runtime version as the tag. How they are
recorded, updated, published and promoted is described in
[Base profiles](release-baseprofiles.md).

`spoc push` produces the runtime format automatically when the input file is a
raw runtime-spec seccomp profile in JSON, for example the output of
`spoc convert`, which writes the profile spec without the fields that are
specific to the operator (`state`, `baseProfileName` and the listener fields):

```
> spoc push -f ./profile.json registry.example.com/profiles/runc:<version>
```

The media type is set on the manifest config as well as on `artifactType`, and
the single layer is not platform qualified:

```
> skopeo inspect --raw docker://registry.example.com/profiles/runc:<version> | jq .
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "artifactType": "application/vnd.cncf.seccomp-profile.config.v1+json",
  "config": {
    "mediaType": "application/vnd.cncf.seccomp-profile.config.v1+json",
    "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
    "size": 2
  },
  "layers": [
    {
      "mediaType": "application/json",
      "digest": "sha256:d6ad0c0d1f2eb0e0b0a2d16a44a8bb5a1e11e8fbc0a90e4e1a36ba4b7d1e3f9c",
      "size": 1031,
      "annotations": {
        "org.opencontainers.image.title": "profile.json"
      }
    }
  ],
  "annotations": {
    "org.opencontainers.image.created": "1970-01-01T00:00:00Z"
  }
}
```

The input has to decode strictly as a runtime-spec seccomp profile: unknown
fields and trailing data are rejected and `defaultAction` is required. Such
artifacts contain exactly one profile, so pushing several platforms into one
artifact is rejected for this format; per-platform variants have to be pushed
as separate artifacts.

Profiles which are neither a profile CRD nor a runtime-spec profile are
rejected, so that no artifact gets published which no consumer understands.
Content that container runtimes reject fails the push, checked with the same
`ValidateArtifact` from the
[merge library](https://github.com/kubernetes-sigs/security-profiles-merger)
that runtimes run: the listener fields, `SCMP_ACT_NOTIFY`, more than 128 rule
entries for one syscall, and unknown architectures, flags or argument
operators. `--disable-artifact-validation` pushes such a profile anyway, which
exists for publishing test fixtures that runtimes are expected to reject.
Profiles above 1 MiB only produce a warning, because the size limit is a
runtime default rather than part of the format.

`spoc pull` and `oci://` base profile references accept both formats. Runtime
format artifacts are recognized by their media type and read from their single
layer, so layer names and annotations do not matter. For other artifacts, the
layer names above are used, with a fallback to the single layer if there is
exactly one and it is not bound to another platform. A runtime format artifact
is exposed as a `SeccompProfile` named after the last path element of the
reference (`runc` for the example above), whose spec drops fields the CRD
cannot express, such as `defaultErrnoRet`. `spoc pull` writes the artifact
content unchanged, so a runtime format artifact is saved as runtime-spec JSON
and the default output file switches to a `.json` extension.

### Using multiple platforms

`spoc push` supports specifying the target platforms for the profiles to be
pushed. This can be done by using the `--platforms` / `-p` together with the
`--profiles` / `-f` flag. `spoc push` and `spoc pull` both accept `--platform`
and `--platforms` as spelling of the flag. For example, to push two profiles
into one artifact:

```
> spoc push -f ./profile-amd64.yaml -p linux/amd64 -f ./profile-arm64.yaml -p linux/arm64 registry.example.com/profiles/test:latest
10:59:17.887884 Pushing profiles to: registry.example.com/profiles/test:latest
10:59:17.887970 Creating file store (dir=/tmp/push-2265359353)
10:59:17.887989 Reading profiles (count=2)
10:59:17.887995 Adding profile to store (file=/home/user/profile-amd64.yaml, platform=linux/amd64)
10:59:17.888193 Adding profile to store (file=/home/user/profile-arm64.yaml, platform=linux/arm64)
10:59:17.888240 Packing files (mediaType=application/vnd.unknown.config.v1+json)
…
```

The pushed artifact now contains both profiles, separated by their platform:

```
> skopeo inspect --raw docker://registry.example.com/profiles/test:latest | jq .
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "artifactType": "application/vnd.unknown.config.v1+json",
  "config": {
    "mediaType": "application/vnd.oci.empty.v1+json",
    "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
    "size": 2
  },
  "layers": [
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar",
      "digest": "sha256:6ddecdf312758a19ec788c3984418541274b3c9daf2b10f687d847bc283b391b",
      "size": 1167,
      "annotations": {
        "org.opencontainers.image.title": "profile-linux-amd64.yaml"
      },
      "platform": {
        "architecture": "amd64",
        "os": "linux"
      }
    },
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar",
      "digest": "sha256:6ddecdf312758a19ec788c3984418541274b3c9daf2b10f687d847bc283b391b",
      "size": 1167,
      "annotations": {
        "org.opencontainers.image.title": "profile-linux-arm64.yaml"
      },
      "platform": {
        "architecture": "arm64",
        "os": "linux"
      }
    }
  ],
  "annotations": {
    "org.opencontainers.image.created": "1970-01-01T00:00:00Z"
  }
}
```

There are a few fallback scenarios included in the CLI:

- If neither a platform nor an input file is specified, then `spoc` will fallback
  to the default profile (`profile.yaml`) and push it without a platform, so
  that it gets pulled on every platform.
- If only one platform is specified, then `spoc` will apply it and use the
  default profile. Several platforms without input files are rejected.
- If only one input file is specified, then `spoc` will push it without a
  platform.
- If multiple platforms and input files are provided, then `spoc` requires them
  to match their occurrences. Platforms have to be unique as well.

The Security Profiles Operator will try to pull the correct profile by using
`runtime.GOOS`/`runtime.GOARCH`, but also falls back to the default profile
(without any platform specified), if it exists. The default variant of an
architecture matches no variant, so `linux/arm64/v8` pulls a profile pushed for
`linux/arm64` and the other way around. Artifacts behind an OCI image index are
resolved to the manifest of the matching platform. Only the selected layer is
downloaded, and artifacts with more than 128 layers are rejected. `spoc pull`
behaves in the same way, for example if a profile does not support any
platform:

```
> spoc pull registry.example.com/profiles/test:latest
11:07:14.788840 Pulling profile from: registry.example.com/profiles/test:latest
11:07:14.788852 Resolving digest of image (image=registry.example.com/profiles/test:latest)
11:07:14.911204 Verifying signature (…)
…
11:07:17.559037 Copying profile from repository
11:07:17.559042 Source image (image=registry.example.com/profiles/test@sha256:…)
11:07:18.359152 Checking profile contents
11:07:18.359209 Reading profile layer (title=profile-linux-amd64.yaml, runtimeFormat=false)
11:07:18.359728 Got SeccompProfile: test-amd64
11:07:18.359732 Saving profile in: profile.yaml
```

We can see from the logs that `spoc` reads the layer of the local platform,
`profile-linux-amd64.yaml`, and it would fall back to a platform independent
`profile.yaml` layer if that did not exist. We can also directly specify which
platform to pull:

```
> spoc pull -p linux/arm64 registry.example.com/profiles/test:latest
11:08:53.355689 Pulling profile from: registry.example.com/profiles/test:latest
…
11:08:57.311964 Reading profile layer (title=profile-linux-arm64.yaml, runtimeFormat=false)
11:08:57.312473 Got SeccompProfile: test-arm64
11:08:57.312476 Saving profile in: profile.yaml
```
