{ pkgs, buildGoModule }:
with pkgs; buildGo121Module rec {
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
    (zstd.override { static = true; })
  ];
  buildPhase = ''
    make
  '';
  installPhase = ''
    install -Dm755 -t $out build/security-profiles-operator build/spoc
  '';
}
