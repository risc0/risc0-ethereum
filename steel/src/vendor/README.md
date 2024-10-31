# Vendored Dependencies

This directory houses source code from external crates that have not been published to [crates.io]. To incorporate their functionality without forking or modifying the original repositories, we have "vendored" them by generating a rust module from their source repository.

## Important Notes

- Vendoring is a temporary solution. It is always preferable to use crates published on [crates.io] whenever possible.
- If the vendored crate is eventually published, remove the vendored copy and add it as a regular dependency in `cargo.toml'.
- Keep the git submodule up to date with the original repository if necessary.

[crates.io]: https://crates.io
