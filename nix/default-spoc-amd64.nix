((import ./nixpkgs.nix {
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
