# Release process

1. For a major or minor release, create a release branch.

   Release branches are initialized with a commit from `main`, and named `release-x.y` where `x.y` is the major and minor version.
   Patch version changes are committed to the release branch matching their major and minor version.

2. Make sure that the [selectors](./contracts/src/selector.rs) are up-to-date.

   If any of the parameters affecting `Groth16ReceiptVerifierParameters` or the `SetInclusionReceiptVerifierParameters` changed, run this command and use the output to update them (this should be done for the main branch and only backport it if necessary):

   > Before running, make sure the const `SET_BUILDER_ID` in the [selector::tests::print_verifier_parameters](./contracts/src/selector.rs) matches with what you are expecting.
   >
   > ```
   > cargo test -F unstable -p risc0-ethereum-contracts -- selector::tests::print_verifier_parameters --exact --show-output
   > ```

3. Create two version bump PRs:

   * One PR should be to the `release-x.y` branch and do the following:

     * Bump the version of the crates to `x.y.z`: `version` under `[workspace.package]` in `./Cargo.toml`, along with the intra-workspace dependency versions in the same file.
     * Update the version string in contracts that contain it:
       * `contracts/src/groth16/RiscZeroGroth16Verifier.sol`: set to the version of the `risc0-zkvm` crate.
       * `contracts/src/RiscZeroSetVerifier.sol`
     * Remove the note at the top of `README.md` about being on the `main` branch.
     * Update `risc0` crate dependencies. In all workspaces:

         > You can find the workspaces with `grep -rl --include="Cargo.toml" '\[workspace\]' --exclude-dir=./lib .`

         * Change the `risc0` crates (e.g. `risc0-zkvm`, `risc0-build`) from `branch = "main"` git dependencies to the latest monorepo release on crates.io.
         * Run `cargo update` in each workspace.

         > Here is a nifty oneliner to do that
         >
         > ```
         > grep -rl --include="Cargo.toml" '\[workspace\]' --exclude-dir=./lib . | sort -u | xargs -n1 cargo update --manifest-path
         > ```

     * Remove `Cargo.lock` from `.gitignore` and commit all lock files.

   * The other PR should:
     * Bump the version on the `main` branch to the next, unreleased, minor version `x.y+1.0-alpha.1`.
     * Update the version string in contracts that contain it:
       * `contracts/src/groth16/RiscZeroGroth16Verifier.sol`
       * `contracts/src/RiscZeroSetVerifier.sol`

4. Run the checks on the release branch.

   There is no CI in this repository, so run these locally before tagging.
   They require `cargo risczero`, `r0vm`, and the RISC Zero toolchains matching the `risc0` release, and [Foundry](https://getfoundry.sh/).

   ```sh
   cargo fmt --all --check
   (cd contracts && forge fmt --check)
   # risc0-ethereum-test-utils needs the built contract artifacts.
   forge build
   cargo clippy --locked --workspace --all-targets --all-features -- -Dwarnings
   cargo test --locked --workspace --all-features
   (cd contracts && forge test -vvv)
   ```

5. Tag the release as `vX.Y.Z`, and add release on GitHub.

   Include a summary of the changes in the release notes.

6. Publish crates to `crates.io`

   Crates currently published to `crates.io` are:

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

7. When changes have been made to the verifier contract, deploy a new verifier contract and add it to the verifier router on each supported chain.

   Refer to [contracts/script/README.md](./contracts/script/README.md) for instructions on the steps involved.

   1. Deploy the verifier contract and schedule the update.

   2. After the timelock delay has passed (7 days on mainnet chains and 1 second on testnet), finish the operation to add the new verifier to the router.

   3. Run the deployment tests to confirm that the state recorded in `deployment.toml` matches the state of the contracts deployed on-chain.

      You can run the tests against a single chain with the following command, with `RPC_URL` set to an Ethereum RPC provider such as Alchemy, with your API key:

      ```sh
      # In the contracts directory.
      FOUNDRY_PROFILE=deployment-test forge test -vv --fork-url="$RPC_URL"
      ```

      You can run the tests against all supported chains with the following oneliner:

      ```sh
      # In the contracts directory.
      for rpcurl in $(yq eval -e ".chains[].rpc-url" deployment_secrets.toml); do FOUNDRY_PROFILE=deployment-test forge test -vv --fork-url="$rpcurl"; done
      ```

   4. Document the new addresses and version in the [dev.risczero.com docs](https://dev.risczero.com/api/blockchain-integration/contracts/verifier).

      Use [contracts/generate_contract_address_table.py](./contracts/generate_contract_address_table.py) to generate the tables. Python 3.11+ is required.

      Also update https://docs.boundless.network/developers/smart-contracts/deployments
