{ pkgs, buildGoModule }:
with pkgs; buildGo120Module rec {
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
    elfutils
    glibc
    glibc.static
    libapparmor
    libbpf_1
    libseccomp
    zlib.static
  ];
  buildPhase = ''
    make WITH_BPF=1
  '';
  installPhase = ''
    install -Dm755 -t $out build/security-profiles-operator build/spoc
  '';
}
