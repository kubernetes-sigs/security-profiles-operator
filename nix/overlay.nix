self: super:
{
  buildGoModule = super.buildGo127Module;

  # The Go release of go.mod, which nixpkgs-unstable may lag behind. Drop the
  # override once nixpkgs has it, make verify-go-version checks the version.
  go_1_27 = super.go_1_27.overrideAttrs (finalAttrs: old: {
    version = "1.27.4"; # golang in dependencies.yaml
    src = super.fetchurl {
      url = "https://go.dev/dl/go${finalAttrs.version}.src.tar.gz";
      hash = "sha256-c8+4VxrsDAEXdofbhxY9Rqog6XeWcncokaoXZU2aYJk=";
    };
  });

  # The overrides rebuild gnutls instead of substituting it, which runs its
  # test suite on every image build. It takes most of the build time and fails
  # intermittently, without testing anything of the operator.
  gnutls = super.gnutls.overrideAttrs (old: {
    doCheck = false;
    configureFlags = (old.configureFlags or [ ]) ++ [ "--disable-doc" ];
    outputs = builtins.filter (o: o != "devdoc" && o != "man") (old.outputs or [ "out" ]);
  });

  # The release libbpfgo is built against, which nixpkgs may lag behind. Bump
  # it together with hack/install-libbpf.sh, see libbpf in dependencies.yaml.
  libbpf = super.libbpf.overrideAttrs (old: rec {
    version = "1.8.0"; # libbpf in dependencies.yaml
    src = super.fetchurl {
      url = "https://github.com/libbpf/libbpf/archive/refs/tags/v${version}.tar.gz";
      sha256 = "b7a1e685f90f6a63ead0dd85d053694b222975da8d09c1a966041cff6f0055ff";
    };
  });

  libseccomp = super.libseccomp.overrideAttrs (x: {
    doCheck = false;
    dontDisableStatic = true;
  });
}
