self: super:
{
  libseccomp = super.libseccomp.overrideAttrs (x: {
    doCheck = false;
    dontDisableStatic = true;
  });
  # TODO: remove when https://github.com/NixOS/nixpkgs/pull/187978 got merged
  libbpf = super.libbpf.overrideAttrs (x: {
    version = "1.0.0";
    src = super.fetchFromGitHub {
      owner = "libbpf";
      repo = "libbpf";
      rev = "v1.0.0";
      sha256 = "sha256-JU/Ia85V4L1DtwRcIn9OF/qt52hYSQhkw2Iz2ovEwqo=";
    };
  });
}
