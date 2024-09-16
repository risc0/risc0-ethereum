# Vendored Dependencies

This directory houses source code from external crates that have not been published to [crates.io]. To incorporate their functionality without forking or modifying the original repositories, we've "vendored" them by copying their source files here and adapting them to function as sub-modules within our project.

## Vendored Crates

### [github.com/ralexstokes/ethereum-consensus@cf3c404043230559660810bc0c9d6d5a8498d819](https://github.com/ralexstokes/ethereum-consensus/tree/cf3c404043230559660810bc0c9d6d5a8498d819)

- The `ethereum-consensus/src` folder was copied (renamed to `ethereum_consensus`).
- The license files (`LICENSE_MIT` and `LICENSE-APACHE`) were also copied into the `ethereum_consensus` folder.
- `ethereum_consensus/lib.rs` was renamed to `ethereum_consensus/mod.rs`.
- A module description was added to `ethereum_consensus/mod.rs`.
- The `ethereum_consensus/bin` folder was removed.
- The `networking` module was removed.
- All instances of "`crate::`" were replaced with "`crate::vendor::ethereum_consensus::`".
- All instances of `#[cfg(feature = "serde")]` were removed to enable all the code behind this feature unconditionally.
- All other `#[cfg(feature = "...")]` attributes and their associated code blocks were removed.
- `cargo fmt --all` was run to format the code.

## Important Notes

- Vendoring is a temporary solution. It is always preferable to use crates published on [crates.io] whenever possible.
- If the vendored crate is eventually published, remove the vendored copy and add it as a regular dependency in `cargo.toml'.
- Keep the vendored code up to date with the original repository if necessary.

[crates.io]: https://crates.io
