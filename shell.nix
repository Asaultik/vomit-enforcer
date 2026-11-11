# `nix-shell` in the repo root gives you everything to build, test and flash.
# ST-Link without root needs udev rules in your NixOS config:
#   services.udev.packages = [ pkgs.stlink pkgs.probe-rs-tools ];
{ pkgs ? import <nixpkgs> { } }:
pkgs.mkShell {
  packages = with pkgs; [
    git
    rustup
    probe-rs-tools
    stlink
    gcc-arm-embedded
    (python3.withPackages (p: [ p.cryptography ]))
  ];
  shellHook = ''
    rustup toolchain install stable --profile minimal -c clippy -c rustfmt >/dev/null 2>&1
    rustup target add thumbv7em-none-eabihf >/dev/null 2>&1
  '';
}
