(import ./nixpkgs.nix {
  crossSystem = {
    config = "aarch64-unknown-linux-gnu";
  };
}).callPackage ./derivation.nix
{ }
