{ pkgs, buildGoModule }:
with pkgs; buildGoModule rec {
  name = "security-profiles-operator";
  src = ./..;
  vendorSha256 = null;
  doCheck = false;
  outputs = [ "out" ];
  nativeBuildInputs = with buildPackages; [
    bpftool
    clang_12
    git
    llvm_12
    pkg-config
    which
  ];
  buildInputs = [
    (libseccomp.overrideAttrs (x: { dontDisableStatic = true; }))
    glibc
    glibc.static
    libbpf
    libelf
    zlib.static
  ];
  buildPhase = ''
    export CLANG=clang-12
    export CFLAGS=$NIX_CFLAGS_COMPILE
    make build/recorder.bpf.o
  '';
  installPhase = ''
    install -Dm644 -t $out build/recorder.bpf.o
  '';
}
