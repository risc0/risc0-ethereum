# Release process

1. For a major or minor release, create a release branch.

   Release branches are initialized with a commit from `main`, and named `release-x.y` where `x.y` is the major and minor version.
   Patch version changes are committed to the release branch matching their major and minor version.

2. Create two version bump PRs:

   * One PR should be to the `release-x.y` branch and do the following:

     <!-- TODO: Write a script (e.g. in Python) to automate as many of these steps as possible. -->
     * Bump the version of all crates in the workspace to `x.y.z`.
     * Remove the note at the top of `README.md` about being on the `main` branch.
     * Change the reference for all `risc0` crates (e.g. `risc0-zkvm`, `bonsai-sdk`) to the latest monorepo release.
     <!-- TODO: Add --locked to checks in CI against the release branch, such that it guarentees the checked in lock files are complete and consistent -->
     * Run `cargo update` in all workspaces. (You can find the workspaces with `grep -R '\[workspace\]' --include Cargo.toml -l .`)
     * Remove `Cargo.lock` from `.gitignore` and commit all lock files.

   * The other PR should bump the version on the `main` branch to the next, unreleased, minor version `x.y+1.0-alpha.1`.

3. Tag the release as `vX.Y.Z`, and add release on GitHub.

   Include a summary of the changes in the release notes.

4. Publish crates to `crates.io`

   Crates currently published to `crates.io` are:

   * `risc0-steel`
   * `risc0-build-ethereum`

   <br/>

   > NOTE: We intend to publish more of the crates in the future.
   > Blocking issue is that the other crates depend on building Solidity smart contracts as part of a `build.rs` script, which makes it incompatible with `crates.io`.

   <!-- TODO: Include the actual commands to publish -->

5. When changes have been made to the verifier contract, deploy a new verifier contract.

    <!-- TODO: Include instructions for the process including the emergency stop and index contracts, once those are ready -->

   * Deploy the contract to Sepolia, and verify the source code.

     Set the `ETHERSCAN_API_KEY` and `ETH_WALLET_PRIVATE_KEY` environment variables to an valid Etherscan API key and Sepolia private key respectively.

     ```sh
     # In the contracts directory
     forge script script/DeployVerifier.s.sol:DeployVerifier --rpc-url $ALCHEMY_API_URL --broadcast --verify -vvvv
     ```

   * Document the new address and version in the `dev.risczero.com` docs.

     [https://dev.risczero.com/api/blockchain-integration/contracts/verifier](https://dev.risczero.com/api/blockchain-integration/contracts/verifier)

6. Open a PR to [risc0-foundry-template](https://github.com/risc0/risc0-foundry-template) updating the references in `Cargo.toml` and in the `lib/risc0` submodule to point to the new release branch.
