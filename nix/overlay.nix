self: super:
{
  # TODO: remove when go 1.24 is the standard in nixpkgs
  buildGoModule = super.buildGo124Module;
  libseccomp = super.libseccomp.overrideAttrs (x: {
    doCheck = false;
    dontDisableStatic = true;
  });
}
