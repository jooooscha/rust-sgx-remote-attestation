{
  inputs.easy.url = "github:jooooscha/easy-flake";

  outputs = { easy, ... }:
    with easy.pkgs;
    easy.rust {
      root = ./.;
      ssl = true;
      inputs = [
        cmake
      ];
    };
}
