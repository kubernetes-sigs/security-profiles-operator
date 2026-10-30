# Examples

These manifests show how to use the Security Profiles Operator. The
[documentation](../doc/README.md) describes them, the table links the section
which uses each of them. The examples marked as such in the table also ship as
the examples of the operator in its OLM bundle, which the OpenShift console
shows.

| File | Section | Bundle |
| ---- | ------- | ------ |
| [`config.yaml`](config.yaml) | The default SPOD, which [`make deploy`](../doc/hacking.md) applies | Yes |
| [`seccompprofile.yaml`](seccompprofile.yaml) | [Quick start](../README.md#quick-start), [Create a seccomp profile](../doc/profiles.md#create-a-seccomp-profile) | Yes |
| [`pod.yaml`](pod.yaml) | [Use a seccomp profile](../doc/profiles.md#use-a-seccomp-profile) | |
| [`baseprofile-runc.yaml`](baseprofile-runc.yaml), [`baseprofile-crun.yaml`](baseprofile-crun.yaml) | [Base syscalls for a container runtime](../doc/profiles.md#base-syscalls-for-a-container-runtime), recorded by CI, see [base profiles](../doc/release-baseprofiles.md) | |
| [`apparmorprofile.yaml`](apparmorprofile.yaml) | [Create an AppArmor profile](../doc/profiles.md#create-an-apparmor-profile) | Yes |
| [`pod-apparmor.yaml`](pod-apparmor.yaml) | [Use an AppArmor profile](../doc/profiles.md#use-an-apparmor-profile) | |
| [`selinuxprofile.yaml`](selinuxprofile.yaml) | [Create a SELinux profile](../doc/profiles.md#create-a-selinux-profile) | Yes |
| [`rawselinuxprofile.yaml`](rawselinuxprofile.yaml) | [Create a raw SELinux profile](../doc/profiles.md#create-a-raw-selinux-profile) | Yes |
| [`profilebinding.yaml`](profilebinding.yaml) | [Bind workloads to profiles](../doc/profiles.md#bind-workloads-to-profiles) | Yes |
| [`profilerecording-seccomp-logs.yaml`](profilerecording-seccomp-logs.yaml) | [Record a seccomp profile with the log enricher](../doc/recording.md#with-the-log-enricher) | |
| [`profilerecording-seccomp-bpf.yaml`](profilerecording-seccomp-bpf.yaml) | [Record a seccomp profile with the BPF recorder](../doc/recording.md#with-the-bpf-recorder) | Yes |
| [`profilerecording-seccomp-specific-container-logs.yaml`](profilerecording-seccomp-specific-container-logs.yaml), [`profilerecording-seccomp-bpf-specific-container.yaml`](profilerecording-seccomp-bpf-specific-container.yaml) | [Record specific containers](../doc/recording.md#record-specific-containers) | |
| [`profilerecording-apparmor-bpf.yaml`](profilerecording-apparmor-bpf.yaml) | [Record an AppArmor profile](../doc/recording.md#record-an-apparmor-profile) | |
| [`profilerecording-selinux-logs.yaml`](profilerecording-selinux-logs.yaml) | [Record a SELinux profile](../doc/recording.md#record-a-selinux-profile) | |
| [`olm/operatorhub-io.yaml`](olm/operatorhub-io.yaml) | [Installation using OLM from operatorhub.io](../doc/installation.md#from-operatorhubio) | |
| [`olm/install-resources.yaml`](olm/install-resources.yaml) | [Installation using OLM from the upstream catalog](../doc/installation.md#from-the-upstream-catalog) | |

The recording examples select the pods labeled `app: alpine`, like the
workloads of the e2e tests which use them.

## Test fixtures

The e2e tests use these files, they are no examples:

- [`seccompprofile-allowed-syscalls-validation.yaml`](seccompprofile-allowed-syscalls-validation.yaml)
  and [`seccompprofile-allowed-syscalls-change.yaml`](seccompprofile-allowed-syscalls-change.yaml)
  test the allowed syscalls of the SPOD.
- [`test-profiles/`](test-profiles) holds raw seccomp profiles, which
  `hack/push-test-artifacts.sh` pushes as OCI artifacts for the `spoc` tests.
