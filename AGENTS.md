# Notes for coding agents

This file is for AI coding agents working on the Security Profiles Operator.
Human contributors find the same information in [CONTRIBUTING.md](CONTRIBUTING.md)
and [doc/hacking.md](doc/hacking.md).

## Where to start

- [doc/hacking.md](doc/hacking.md) describes the build, the optional features,
  the unit and e2e tests, the e2e environment variables and the quarantine of
  flaky e2e test cases.
- `make help` lists the `Makefile` targets with a description.
- [doc/security-model.md](doc/security-model.md) documents the privileges of
  every container and role. Update it together with the manifests,
  `hack/verify-security-model.sh` checks the profile names and API groups.

## Building and testing

- Without the native libraries (libbpf, libelf, libseccomp, libapparmor),
  build with `BPF_ENABLED=0 APPARMOR_ENABLED=0 make`, or use the Nix targets.
- Rely on CI for the heavy checks. Locally, stick to quick compile checks like
  `go build ./...`, `go vet -tags e2e ./test/...` and the unit tests of the
  packages you changed. Do not run the e2e suite, `make verify` or the full
  linter unless asked to: they need a cluster or take a long time.
- The e2e tests only build with the `e2e` build tag. New e2e test cases start
  quarantined with `flaky: true`, see doc/hacking.md.

## Generated files

Do not edit generated files by hand, regenerate them:

- `make update-mocks` for the counterfeiter fakes.
- `make manifests generate deployments` after API or RBAC marker changes.
- `make bundle` for the OLM bundle below `bundle/`, which also embeds the
  examples of `examples/`.
- `make update-toc` for the tables of contents of the documentation.
- `make update-bpf` for the BPF objects, which needs Nix.

## Things to leave alone

- Never bump the Flatcar box of the e2e VM (3510.2.3 in
  `hack/ci/Vagrantfile-flatcar`). It is pinned on purpose.
- Do not edit the base profiles `examples/baseprofile-*.yaml` by hand, CI
  records them, see [doc/release-baseprofiles.md](doc/release-baseprofiles.md).
