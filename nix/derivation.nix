{ pkgs, buildGoModule }:
with pkgs; buildGoModule rec {
  name = "security-profiles-operator";
  src = builtins.filterSource
    (path: type: !(type == "directory" && baseNameOf path == "build")) ./..;
  vendorSha256 = null;
  doCheck = false;
  outputs = [ "out" ];
  nativeBuildInputs = with buildPackages; [
    git
    pkg-config
    which
  ];
  buildInputs = [
    (libseccomp.overrideAttrs (x: { dontDisableStatic = true; }))
    glibc
    glibc.static
    libbpf
    libelf
    libapparmor
    zlib.static
  ];
  buildPhase = ''
    make WITH_BPF=1
  '';
  installPhase = ''
    install -Dm755 -t $out build/security-profiles-operator
  '';
}
