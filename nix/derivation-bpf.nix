{ pkgs, buildGoModule, arch ? "x86" }:
with pkgs; buildGoModule rec {
  name = "security-profiles-operator";
  src = lib.cleanSourceWith {
    src = nix-gitignore.gitignoreSourcePure [ ../.gitignore ] ./..;
    filter = path: type: builtins.match ".*\\.bpf\\.o\\.[a-z0-9]+" path == null;
  };
  vendorHash = null;
  doCheck = false;
  outputs = [ "out" ];
  nativeBuildInputs = with buildPackages; [
    git
    llvmPackages_19.clang-unwrapped
    llvm_19
    pkg-config
    which
  ];
  buildInputs = [
    glibc
    glibc.static
    libbpf
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
