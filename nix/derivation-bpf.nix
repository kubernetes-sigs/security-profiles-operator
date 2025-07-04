{ pkgs, buildGoModule, arch ? "x86" }:
with pkgs; buildGoModule rec {
  name = "security-profiles-operator";
  # Use Pure to avoid exuding the .git directory
  src = nix-gitignore.gitignoreSourcePure [ ../.gitignore ] ./..;
  vendorHash = null;
  doCheck = false;
  outputs = [ "out" ];
  nativeBuildInputs = with buildPackages; [
    git
    llvmPackages_18.clang-unwrapped
    llvm_18
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
    make build/enricher.bpf.o
  '';
  installPhase = ''
    install -Dm644 -t $out build/recorder.bpf.o
    install -Dm644 -t $out build/enricher.bpf.o
  '';
}
