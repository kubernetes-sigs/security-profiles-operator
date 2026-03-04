self: super:
{
  buildGoModule = super.buildGo126Module;

  gnutls = super.gnutls.overrideAttrs (old: {
    configureFlags = (old.configureFlags or [ ]) ++ [ "--disable-doc" ];
    outputs = builtins.filter (o: o != "devdoc" && o != "man") (old.outputs or [ "out" ]);
  });

  libseccomp = super.libseccomp.overrideAttrs (x: {
    doCheck = false;
    dontDisableStatic = true;
  });
}
