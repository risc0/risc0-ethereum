# Release process

1. For a major or minor release, create a release branch.

   Release branches are initialized with a commit from `main`, and named `release-x.y` where `x.y` is the major and minor version.
   Patch version changes are committed to the release branch matching their major and minor version.

2. Create two version bump PRs:

   * One PR should be to the `release-x.y` branch and do the following:

     <!-- TODO: Write a script (e.g. in Python) to automate as many of these steps as possible. -->
     * Bump the version of all crates in the workspace to `x.y.z`. Workspace crate versions are specified in `./Cargo.toml`.
     * Update the version string in contracts that contain it:
       * `contracts/src/groth16/RiscZeroGroth16Verifier.sol`
     * Update references to the `main` branch
       * Search for `risc0/risc0-ethereum/refs/heads/main`
     * Update `steel/CHANGELOG.md` to ensure it details the changes to be released.
     * Remove the note at the top of `README.md` about being on the `main` branch.
     * Update `risc0` crate dependencies. In all workspaces:
         >  You can find the workspaces with `grep -R '\[workspace\]' --include Cargo.toml -l .`
         * Change the reference for `risc0` crates (e.g. `risc0-zkvm`, `bonsai-sdk`) to the latest monorepo release.
         <!-- TODO: Add --locked to checks in CI against the release branch, such that it guarantees the checked in lock files are complete and consistent -->
         * Run `cargo update`.
     * Remove `Cargo.lock` from `.gitignore` and commit all lock files.

   * The other PR should:
     * Bump the version on the `main` branch to the next, unreleased, minor version `x.y+1.0-alpha.1`.
     * Update the version string in contracts that contain it:
       * `contracts/src/groth16/RiscZeroGroth16Verifier.sol`
     * Update `steel/CHANGELOG.md` to start a new section for the next release.

3. Tag the release as `vX.Y.Z`, and add release on GitHub.

   Also tag the release as `steel-v0.X.Y`, as long as Steel is pre-1.0 and so on a different version than the rest of the crates.

   Include a summary of the changes in the release notes.

4. Publish crates to `crates.io`

   Crates currently published to `crates.io` are:

   * ~~`risc0-steel`~~

     > NOTE: risc0-steel currently cannot be published to crates.io.
     > See [#202](https://github.com/risc0/risc0-ethereum/issues/202)

   * `risc0-build-ethereum`
   * `risc0-ethereum-contracts`

   > NOTE: When publishing a new crate, make sure to add github:risc0:maintainers as an owner.

   <br/>

   ```sh
   # Log in to crates.io. Create a token that is restricted to what you need to do (e.g. publish update) and set an expiry.
   cargo login
   # Dry run to check that the package will publish. Look through the output, e.g. at version numbers, to confirm it makes sense.
   cargo publish -p $PKG --dry-run
   # Actually publish the crate
   cargo publish -p $PKG
   ```

   See the [Cargo docs](https://doc.rust-lang.org/cargo/reference/publishing.html) for more details.

5. When changes have been made to the verifier contract, deploy a new verifier contract and add it to the verifier router on each supported chain.

   Refer to [contracts/script/README.md](./contracts/script/README.md) for instructions on the steps involved.

   1. Deploy the verifier contract and schedule the update.

   2. After the timelock delay has passed (7 days on mainnet chains and 1 second on testnet), finish the operation to add the new verifier to the router.

   3. Run the deployment tests to confirm that the state recorded in `deployment.toml` matches the state of the contracts deployed on-chain.

      You can run the tests against a single chain with the following command:

      ```sh
      # In the contracts directory.
      FOUNDRY_PROFILE=deployment-test forge test -vv --fork-url="$RPC_URL"
      ```

      You can run the tests against all supported chains with the following oneliner:

      ```sh
      # In the contracts directory.
      for rpcurl in $(yq eval -e ".chains[].rpc-url" deployment_secrets.toml); do FOUNDRY_PROFILE=deployment-test forge test -vv --fork-url="$rpcurl"; done
      ```

   4. Document the new addresses and version in the `dev.risczero.com` docs.

     Use [contracts/generate_contract_address_table.py] to generate the tables. Python 3.11+ is required.

     [https://dev.risczero.com/api/blockchain-integration/contracts/verifier](https://dev.risczero.com/api/blockchain-integration/contracts/verifier)

6. Open a PR to [risc0-foundry-template](https://github.com/risc0/risc0-foundry-template) updating the references in `Cargo.toml` and in the `lib/risc0` submodule to point to the new release branch.
