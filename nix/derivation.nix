{ pkgs, buildGoModule }:
with pkgs; buildGo119Module rec {
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
    (libseccomp.overrideAttrs (x: {
      doCheck = false;
      dontDisableStatic = true;
    }))
    elfutils
    glibc
    glibc.static
    libapparmor
    libbpf
    zlib.static
  ];
  buildPhase = ''
    make WITH_BPF=1
  '';
  installPhase = ''
    install -Dm755 -t $out build/security-profiles-operator
  '';
}
