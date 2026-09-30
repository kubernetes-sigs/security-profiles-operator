{
  description = "Security Profiles Operator";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
  };

  outputs =
    { self, nixpkgs }:
    let
      supportedSystems = [ "x86_64-linux" "aarch64-linux" ];

      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;

      crossTargets = {
        amd64 = null;
        arm64 = {
          config = "aarch64-unknown-linux-gnu";
        };
        ppc64le = {
          config = "powerpc64le-unknown-linux-gnu";
        };
        s390x = {
          config = "s390x-unknown-linux-musl";
        };
      };

      # The BPF objects exist for these architectures only, the ones with
      # vmlinux headers in internal/pkg/daemon/bpfrecorder/vmlinux. The
      # binaries of the other architectures get built without them.
      bpfArchMap = {
        amd64 = "x86";
        arm64 = "arm64";
      };

      mkPkgs =
        system: crossSystem:
        import nixpkgs {
          inherit system;
          crossSystem = crossSystem;
          overlays = [ (import ./nix/overlay.nix) ];
        };

      mkSPO =
        system: crossSystem:
        let
          pkgs = mkPkgs system crossSystem;
        in
        pkgs.callPackage ./nix/derivation.nix { };

      mkBPF =
        system: crossSystem: arch:
        let
          pkgs = mkPkgs system crossSystem;
        in
        pkgs.callPackage ./nix/derivation-bpf.nix { inherit arch; };

      mkSPOC =
        system: crossSystem:
        (mkSPO system crossSystem).overrideAttrs (_: {
          buildPhase = ''
            make build/spoc
          '';
          installPhase = ''
            install -Dm755 -t $out build/spoc
          '';
        });

      # Map target config to native nix system string
      configToSystem = {
        "x86_64-unknown-linux-gnu" = "x86_64-linux";
        "aarch64-unknown-linux-gnu" = "aarch64-linux";
      };
    in
    {
      packages = forAllSystems (
        system:
        let
          native = mkSPO system null;
        in
        {
          default = native;
        }
        // nixpkgs.lib.mapAttrs' (
          arch: crossSystem:
          nixpkgs.lib.nameValuePair "spo-${arch}" (
            if crossSystem == null || (configToSystem.${crossSystem.config} or null) == system then
              native
            else
              mkSPO system crossSystem
          )
        ) crossTargets
        // nixpkgs.lib.mapAttrs' (
          arch: bpfArch:
          nixpkgs.lib.nameValuePair "bpf-${arch}" (
            mkBPF system crossTargets.${arch} bpfArch
          )
        ) bpfArchMap
        // nixpkgs.lib.mapAttrs' (
          arch: crossSystem:
          let
            # spoc s390x uses gnu, not musl
            spocCrossSystem =
              if arch == "s390x" then { config = "s390x-unknown-linux-gnu"; }
              else crossSystem;
          in
          nixpkgs.lib.nameValuePair "spoc-${arch}" (
            if spocCrossSystem == null || (configToSystem.${spocCrossSystem.config} or null) == system then
              mkSPOC system null
            else
              mkSPOC system spocCrossSystem
          )
        ) crossTargets
      );

      # The development environment, `nix develop`: the Go toolchain and the
      # C libraries of the build, plus the tools of the Makefile targets
      # (BPF, protobuf, formatting and the e2e tests).
      devShells = forAllSystems (
        system:
        let
          pkgs = mkPkgs system null;
        in
        {
          default = pkgs.mkShell {
            inputsFrom = [ (mkSPO system null) ];
            packages = with pkgs; [
              clang
              clang-tools
              gnumake
              jq
              kind
              kubectl
              kubernetes-helm
              llvm
              protobuf
              shellcheck
              yq-go
            ];
          };
        }
      );
    };
}
