self: super:
{
  # TODO: remove when go 1.24 is the standard in nixpkgs
  buildGoModule = super.buildGo124Module;

  # TODO: remove when https://github.com/NixOS/nixpkgs/issues/373516 got resolved
  elfutils = super.elfutils.overrideAttrs (x: {
    version = "0.191";
    src = super.fetchurl {
      url = "https://sourceware.org/elfutils/ftp/0.191/elfutils-0.191.tar.bz2";
      hash = "sha256-33bbcTZtHXCDZfx6bGDKSDmPFDZ+sriVTvyIlxR62HE=";
    };
    doCheck = false;
    doInstallCheck = false;
  });

  libseccomp = super.libseccomp.overrideAttrs (x: {
    doCheck = false;
    dontDisableStatic = true;
  });
}
