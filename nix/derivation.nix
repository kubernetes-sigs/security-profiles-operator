{ pkgs, buildGoModule }:
with pkgs; buildGoModule rec {
  name = "security-profiles-operator";
  # Use Pure to avoid exuding the .git directory
  src = nix-gitignore.gitignoreSourcePure [ ../.gitignore ] ./..;
  vendorHash = null;
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
