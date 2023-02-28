{ pkgs, buildGoModule, arch ? "x86" }:
with pkgs; buildGo120Module rec {
  name = "security-profiles-operator";
  src = builtins.filterSource
    (path: type: !(type == "directory" && baseNameOf path == "build")) ./..;
  vendorSha256 = null;
  doCheck = false;
  outputs = [ "out" ];
  nativeBuildInputs = with buildPackages; [
    git
    llvmPackages_15.clang-unwrapped
    llvm_15
    pkg-config
    which
  ];
  buildInputs = [
    glibc
    glibc.static
    libbpf_1
    libseccomp
    zlib.static
  ];
  buildPhase = ''
    export CFLAGS=$NIX_CFLAGS_COMPILE
    export ARCH=${arch}
    make build/recorder.bpf.o
  '';
  installPhase = ''
    install -Dm644 -t $out build/recorder.bpf.o
  '';
}
