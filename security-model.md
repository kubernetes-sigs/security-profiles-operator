# Security Model

This security model aims to clarify the project's current security position against industry 
recommendations and general security best practices. The information provided here should make 
it easier for security teams from highly regulated sectors to assess and use SPO for their workloads.

The SPO project strives to maintain the [least privilege principle], by trying to run with 
the bare minimum privileges for the least amount of time possible. This approach decreases
the attack surface and the window of opportunity in which it can be abused.

Note that this is an on-going effort, and may change over time as new features are developed.

## Host Isolation (a.k.a. Pod Security / Security Context)

Details the security requirements to run SPO from a host isolation perspective. 

### Initialisation

Seccomp leverages an init container to setup an initial symlink as `root`, so it can then operate
 as a non-root user.

During initialisation it also uses the capabilities:

- `CHOWN`
- `FOWNER`
- `FSETID`
- `DAC_OVERRIDE`


### Running Mode

The running permissions for the three core technologies supported: 

|                                  | Seccomp     | SELinux     | AppArmor    |
|----------------------------------|:-----------:|:-----------:|:-----------:|
|               Requires root user | No          | Yes         | Yes         |
|                 Requires HostPID | No          | No          | Yes         |
|  Requires "privileged container" | No          | No          | Yes         |
|     Requires SSH Access to nodes | No          | No          | No          |
| Access to host's mount namespace | No          | Yes         | On Demand   |
|                 AppArmor Profile | `default`   | `default`   | `default`   |
|                     SELinux type | `spc_t`     | `spc_t`     | `spc_t`     |
|                  Seccomp Profile | `unconfined`| `unconfined`| `unconfined`|


#### Host Paths

Throughout their operation they require read and write permissions into host paths:

- `/var/lib/kubelet/seccomp`
- `/etc/selinux.d`
- `/etc/apparmor.d`

### Profile Generation Mode (auto-generating security profiles)

Profile generation features are optional and are not indented to be executed at production environments. 
Ideally such features would be used as part of your software development lifecycle, so you can detect and 
respond to change in profiles, which can _later_ be enforced once deployed in production.

During the execution in profile generation mode, the observed applications may run less restricted than it 
would otherwise, to allow for their operations to be observed and recorded. Keep this in mind when using it
against workloads you may not trust.

|                                  | Seccomp     | SELinux     | AppArmor    |
|----------------------------------|:-----------:|:-----------:|:-----------:|
|               Requires root user | Yes         | Yes         | Yes         |
|                 Requires HostPID | Yes         | Yes         | Yes         |
|  Requires "privileged container" | No          | Yes         | Yes         |
|     Requires SSH Access to nodes | No          | No          | No          |
|                 AppArmor Profile | `default`   | `default`   | `default`   |
|                     SELinux type | `spc_t`     | `spc_t`     | `spc_t`     |
|                  Seccomp Profile | `unconfined`| `unconfined`| `unconfined`|


## Control Plane RBAC

The project's RBAC requirements are managed in an automated manner based on `+kubebuilder:rbac:` tags. 
To map what code requires which permissions, [search this repo](https://github.com/kubernetes-sigs/security-profiles-operator/search?q=%22%2Bkubebuilder%3Arbac%3A%22&type=code) for it.

At control plane level the [least privilege principle] should also be observed. 
A high-level summary of object types accessed outside the `security-profiles-operator` namespace:

### security-profiles-operator

- daemonsets
- daemonsets/finalizers
- deployments
- configmaps
- events
- pods
- servicemonitors

### spod

- daemonsets
- subjectaccessreviews
- tokenreviews
- subjectaccessreviews
- events
- nodes
- pods

### spo-webhook

- events
- pods


For the most up-to-date rbac requirements refer to the materialised [role.yaml](deploy/base/role.yaml) file.

## OCI artifact signature verification

Base profiles can be distributed as OCI artifacts and are signature verified on
pull. Verification is controlled through the `spod` resource:

```yaml
spec:
  security:
    disableOciArtifactSignatureVerification: false
    allowedIdentityRegexp: ".*"
    allowedOidcIssuerRegexp: ".*"
```

The shipped defaults for `allowedIdentityRegexp` and `allowedOidcIssuerRegexp`
match any value. With those defaults a signature is accepted regardless of who
produced it, which only proves that the artifact was signed by somebody. An
attacker able to publish to the referenced registry can sign with their own
Fulcio identity and pass verification.

Constrain both fields to the signers you actually trust, for example:

```yaml
spec:
  security:
    allowedIdentityRegexp: "^https://github\\.com/my-org/my-profiles/"
    allowedOidcIssuerRegexp: "^https://token\\.actions\\.githubusercontent\\.com$"
```

The operator logs a warning when it recognises an unconstrained signer pattern,
such as the shipped default, so an unintentionally permissive configuration is
visible in the spod logs. That detection is best effort: an arbitrary regexp
which happens to accept everything cannot be recognised as such.

[least privilege principle]: https://en.wikipedia.org/wiki/Principle_of_least_privilege
