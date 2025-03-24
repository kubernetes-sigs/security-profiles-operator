(import ./nixpkgs.nix {
  crossSystem = {
    config = "s390x-unknown-linux-musl";
  };
  overlays = [ (import ./overlay.nix) ];
}).callPackage ./derivation-bpf.nix
{ arch = "s390x"; }
