self: super:
{
  buildGoModule = super.buildGo127Module;

  gnutls = super.gnutls.overrideAttrs (old: {
    configureFlags = (old.configureFlags or [ ]) ++ [ "--disable-doc" ];
    outputs = builtins.filter (o: o != "devdoc" && o != "man") (old.outputs or [ "out" ]);
  });

  # The release libbpfgo is built against, which nixpkgs may lag behind. Bump
  # it together with hack/install-libbpf.sh, see libbpf in dependencies.yaml.
  libbpf = super.libbpf.overrideAttrs (old: rec {
    version = "1.8.0";
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
