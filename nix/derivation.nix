{ pkgs, buildGoModule }:
with pkgs; buildGoModule rec {
  name = "security-profiles-operator";
  # Only the inputs the build actually reads. Taking the whole worktree makes
  # every docs, workflow or hack script change alter the derivation hash, which
  # costs every nix CI job a full rebuild instead of a cache hit.
  src = lib.fileset.toSource {
    root = ./..;
    fileset = lib.fileset.unions [
      ../api
      ../cmd
      ../internal
      ../vendor
      ../go.mod
      ../go.sum
      ../Makefile
      ../VERSION
    ];
  };
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
    libbpf
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
