{ pkgs, buildGoModule }:
with pkgs; buildGoModule rec {
  name = "security-profiles-operator";
  src = ./..;
  vendorSha256 = null;
  doCheck = false;
  outputs = [ "out" ];
  nativeBuildInputs = with buildPackages; [
    git
    pkg-config
    which
  ];
  buildInputs = [
    glibc
    glibc.static
    (libseccomp.overrideAttrs (x: { dontDisableStatic = true; }))
  ];
  buildPhase = ''
    make
  '';
  installPhase = ''
    install -Dm755 -t $out build/*
  '';
}
