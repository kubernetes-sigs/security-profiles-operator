[Installation and Usage](installation-usage.md) | [Installation](installation.md) | [Profiles](profiles.md) | **CLI** | [Metrics](metrics.md) | [Troubleshooting](troubleshooting.md)

<!-- toc -->
- [Command Line Interface (CLI)](#command-line-interface-cli)
  - [Record seccomp profiles for a command](#record-seccomp-profiles-for-a-command)
  - [Run commands with seccomp profiles](#run-commands-with-seccomp-profiles)
  - [Pull security profiles from OCI registries](#pull-security-profiles-from-oci-registries)
  - [Push security profiles to OCI registries](#push-security-profiles-to-oci-registries)
  - [Using multiple platforms](#using-multiple-platforms)
<!-- /toc -->

## Command Line Interface (CLI)

The Security Profiles Operator CLI `spoc` aims to support use cases where
Kubernetes is not available at all (for example in edge scenarios). It targets
to provide re-used functionality from the operator itself, especially for
development and testing environments. In the future, we plan to extend the CLI
to interact with the operator itself.

For now, the CLI is able to:

- Record seccomp profiles for a command in YAML (CRD) and JSON (OCI) format.
- Run commands with applied seccomp profiles in both formats.

`spoc` can be retrieved either by downloading the statically linked binary
directly from the [available releases][releases], or by running it within the
official container images:

```console
> podman run -it gcr.io/k8s-staging-sp-operator/security-profiles-operator:latest spoc
NAME:
   spoc - Security Profiles Operator CLI

USAGE:
   spoc [global options] command [command options] [arguments...]

COMMANDS:
   version, v  display detailed version information
   record, r   run a command and record the security profile
   run, x      run a command using a security profile
   help, h     Shows a list of commands or help for one command
```

<!-- TODO: add thoughts about required privileges to run spoc in containers -->

[releases]: https://github.com/kubernetes-sigs/security-profiles-operator/releases/latest

### Record seccomp profiles for a command

To record a seccomp profile via `spoc`, run the corresponding subcommand
followed by any command and arguments:

```console
> sudo spoc record echo test
2023/03/10.10.09:09 Loading bpf module
…
2023/03/10.10.09:13 Adding base syscalls: capget, capset, chdir, …
2023/03/10.10.09:13 Wrote seccomp profile to: /tmp/profile.yaml
2023/03/10.10.09:13 Unloading bpf module
```

Now the seccomp profile should be written in the CRD format:

```console
> cat /tmp/profile.yaml
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
status: {}
```

The output file path can be specified as well by using `spoc record
-o/--output-file`.

We can see that `spoc` automatically adds required base syscalls for OCI
container runtimes to ensure compatibility with them to allow using the profile
within Kubernetes. This behavior can be disabled by using `spoc record
-n/--no-base-syscalls`, or by specifying custom syscalls via `spoc record
-b/--base-syscalls`.

It is also possible to change the format to JSON via `spoc record -t/--type
raw-seccomp`:

```console
> sudo spoc record -t raw-seccomp echo test
…
2023/03/10 10:15:17 Wrote seccomp profile to: /tmp/profile.json
2023/03/10 10:15:17 Unloading bpf module
```

```console
> jq . /tmp/profile.json
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

### Run commands with seccomp profiles

If we now want to test the resulting profile, then `spoc` is able to run any
command by using seccomp profiles via `spoc run`:

```console
> sudo spoc run -p /tmp/profile.yaml echo test
2023/03/10 10:20:00 Reading file /tmp/profile.json
2023/03/10 10:20:00 Setting up seccomp
2023/03/10 10:20:00 Load seccomp profile
2023/03/10 10:20:00 Running command with PID: 567625
test
```

If we now modify the profile, for example by forbidding `chmod`:

```console
> jq 'del(.syscalls[0].names[] | select(. | contains("chmod")))' /tmp/profile.json > /tmp/profile-chmod.json
```

Then running `chmod` via `spoc run` will now throw an error, because the syscall
is not allowed any more:

```console
> sudo spoc run -p /tmp/profile-chmod.json chmod +x /tmp/profile-chmod.json
2023/03/10 10:25:38 Reading file /tmp/profile-chmod.json
2023/03/10 10:25:38 Setting up seccomp
2023/03/10 10:25:38 Load seccomp profile
2023/03/10 10:25:38 Running command with PID: 594242
chmod: changing permissions of '/tmp/profile-chmod.json': Operation not permitted
2023/03/10 10:25:38 Command did not exit successfully: exit status 1
```

### Pull security profiles from OCI registries

The `spoc` client is able to pull security profiles from OCI artifact compatible
registries. To do that, just run `spoc pull`:

```console
> spoc pull ghcr.io/security-profiles/runc:v1.5.1
16:32:29.795597 Pulling profile from: ghcr.io/security-profiles/runc:v1.5.1
16:32:29.795610 Verifying signature

Verification for ghcr.io/security-profiles/runc:v1.5.1 --
The following checks were performed on each of these signatures:
  - Existence of the claims in the transparency log was verified offline
  - The code-signing certificate was verified using trusted certificate authority certificates

[{"critical":{"identity":{"docker-reference":"ghcr.io/security-profiles/runc"},…}}]
16:32:33.208695 Creating file store in: /tmp/pull-3199397214
16:32:33.208713 Verifying reference: ghcr.io/security-profiles/runc:v1.5.1
16:32:33.208718 Creating repository for ghcr.io/security-profiles/runc
16:32:33.208742 Using tag: v1.5.1
16:32:33.208743 Copying profile from repository
16:32:34.119652 Reading profile
16:32:34.119677 Trying to unmarshal seccomp profile
16:32:34.120114 Got SeccompProfile: runc-v1.5.1
16:32:34.120119 Saving profile in: /tmp/profile.yaml
```

The profile can be now found in `/tmp/profile.yaml` or the specified output file
`--output-file` / `-o`. If username and password authentication is required,
either use the `--username`, `-u` flag or export the `USERNAME` environment
variable. To set the password, export the `PASSWORD` environment variable.

### Push security profiles to OCI registries

The `spoc` client is also able to push security profiles from OCI artifact
compatible registries. To do that, just run `spoc push`:

```
> export USERNAME=my-user
> export PASSWORD=my-pass
> spoc push -f ./examples/baseprofile-crun.yaml ghcr.io/security-profiles/crun:v1.8.1
16:35:43.899886 Pushing profile ./examples/baseprofile-crun.yaml to: ghcr.io/security-profiles/crun:v1.8.1
16:35:43.899939 Creating file store in: /tmp/push-3618165827
16:35:43.899947 Adding profile to store: ./examples/baseprofile-crun.yaml
16:35:43.900061 Packing files
16:35:43.900282 Verifying reference: ghcr.io/security-profiles/crun:v1.8.1
16:35:43.900310 Using tag: v1.8.1
16:35:43.900313 Creating repository for ghcr.io/security-profiles/crun
16:35:43.900319 Using username and password
16:35:43.900321 Copying profile to repository
16:35:46.976108 Signing container image
Generating ephemeral keys...
Retrieving signed certificate...

        Note that there may be personally identifiable information associated with this signed artifact.
        This may include the email address associated with the account with which you authenticate.
        This information will be used for signing this artifact and will be stored in public transparency logs and cannot be removed later.

By typing 'y', you attest that you grant (or have permission to grant) and agree to have this information stored permanently in transparency logs.
Your browser will now be opened to:
https://oauth2.sigstore.dev/auth/auth?access_type=…
Successfully verified SCT...
tlog entry created with index: 16520520
Pushing signature to: ghcr.io/security-profiles/crun
```

We can specify a username and password in the same way as for `spoc pull`.
Please also note that signing is always required for push and pull. It is
possible to add custom annotations to the security profile by using the
`--annotations` / `-a` flag multiple times in `KEY:VALUE` format.

### Using multiple platforms

`spoc push` supports specifying the target platforms for the profiles to be
pushed. This can be done by using the `--platforms` / `-p` together with the
`--profiles` / `-p` flag. For example, to push two profiles into one artifact:

```
> spoc push -f ./profile-amd64.yaml -p linux/amd64 -f ./profile-arm64.yaml -p linux/arm64 ghcr.io/security-profiles/test:latest
10:59:17.887884 Pushing profiles to: ghcr.io/security-profiles/test:latest
10:59:17.887970 Creating file store in: /tmp/push-2265359353
10:59:17.887989 Adding 2 profiles
10:59:17.887995 Adding profile ./profile-arm64.yaml for platform linux/arm64 to store
10:59:17.888193 Adding profile ./profile-amd64.yaml for platform linux/amd64 to store
10:59:17.888240 Packing files
…
Pushing signature to: ghcr.io/security-profiles/test
```

The pushed artifact now contains both profiles, separated by their platform:

```
> skopeo inspect --raw docker://ghcr.io/security-profiles/test:latest | jq .
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "config": {
    "mediaType": "application/vnd.unknown.config.v1+json",
    "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
    "size": 2
  },
  "layers": [
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
    },
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
    }
  ],
  "annotations": {
    "org.opencontainers.image.created": "2023-04-28T08:59:17Z"
  }
}
```

There are a few fallback scenarios included in the CLI:

- If neither a platform nor an input file is specified, then `spoc` will fallback
  to the default profile (`/tmp/profile.yaml`) and platform
  (`runtime.GOOS`/`runtime.GOARCH`).
- If only one platform is specified, then `spoc` will apply it and use the
  default profile.
- If only one input file is specified, then `spoc` will apply it and use the
  default platform.
- If multiple platforms and input files are provided, then `spoc` requires them
  to match their occurrences. Platforms have to be unique as well.

The Security Profiles Operator will try to pull the correct profile by using
`runtime.GOOS`/`runtime.GOARCH`, but also falls back to the default profile
(without any platform specified), if it exists. `spoc pull` behaves in the same
way, for example if a profile does not support any platform:

```
> spoc pull ghcr.io/security-profiles/runc:v1.5.1
11:07:14.788840 Pulling profile from: ghcr.io/security-profiles/runc:v1.5.1
11:07:14.788852 Verifying signature
…
11:07:17.559037 Copying profile from repository
11:07:18.359152 Trying to read profile: profile-linux-amd64.yaml
11:07:18.359209 Trying to read profile: profile.yaml
11:07:18.359224 Trying to unmarshal seccomp profile
11:07:18.359728 Got SeccompProfile: runc-v1.5.1
11:07:18.359732 Saving profile in: /tmp/profile.yaml
```

We can see from the logs that `spoc` tries to read `profile-linux-amd64.yaml`,
and if that does not work it falls back to `profile.yaml`. We can also directly
specify which platform to pull:

```
> spoc pull -p linux/arm64 ghcr.io/security-profiles/test:latest
11:08:53.355689 Pulling profile from: ghcr.io/security-profiles/test:latest
11:08:53.355724 Verifying signature
…
11:08:56.229418 Copying profile from repository
11:08:57.311964 Trying to read profile: profile-linux-arm64.yaml
11:08:57.311981 Trying to unmarshal seccomp profile
11:08:57.312473 Got SeccompProfile: crun-v1.8.4
11:08:57.312476 Saving profile in: /tmp/profile.yaml
```
