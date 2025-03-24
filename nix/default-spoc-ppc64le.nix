((import ./nixpkgs.nix {
  crossSystem = {
    config = "powerpc64le-unknown-linux-gnu";
  };
  overlays = [ (import ./overlay.nix) ];
}).callPackage ./derivation.nix
  { }).overrideAttrs (x: {
  buildPhase = ''
    make build/spoc
  '';

  installPhase = ''
    install -Dm755 -t $out build/spoc
  '';
})
