# `nix-shell` in the repo root gives you everything to build, test and flash.
#
# Without root, the ST-Link, the RP2040's boot mode and the FIDO device need
# udev rules. In your NixOS config:
#   services.udev.packages = [ pkgs.probe-rs-tools pkgs.picotool pkgs.libfido2 ];
{ pkgs ? import <nixpkgs> { } }:
pkgs.mkShell {
  packages = with pkgs; [
    git
    rustup
    probe-rs-tools # flashes the STM32 through the ST-Link, shows its logs
    stlink
    gcc-arm-embedded
    picotool # flashes the RP2040 over USB
    libfido2 # fido2-token and friends
    cryptsetup
    (python3.withPackages (p: [ p.cryptography p.fido2 ]))
  ];
  # tests/test_libfido2.py loads the library from here.
  LIBFIDO2 = "${pkgs.libfido2}/lib/libfido2.so";
  shellHook = ''
    rustup toolchain install stable --profile minimal -c clippy -c rustfmt >/dev/null 2>&1
    rustup target add thumbv7em-none-eabihf thumbv6m-none-eabi >/dev/null 2>&1
  '';
}
