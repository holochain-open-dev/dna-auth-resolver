let
  holonixRev = "3bcb40e0b8e059ef2f9c9f836f9913608cb8b002";

  holonixPath = builtins.fetchTarball "https://github.com/holochain/holonix/archive/${holonixRev}.tar.gz";
  holonix = import (holonixPath) {
    holochainVersionId = "v0_0_162";
  };
  nixpkgs = holonix.pkgs;
in nixpkgs.mkShell {
  inputsFrom = [ holonix.main ];
  packages = with nixpkgs; [
    # :TODO: binaryen, wasm-opt?
    # Additional packages go here
    nodejs-16_x
    nodePackages.pnpm
  ];
}
