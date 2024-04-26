# Release process

1. For a major or minor release, create a release branch.

   Release branches are initialized with a commit from `main`, and named `release-x.y` where `x.y` is the major and minor version.
   Patch version changes are committed to the release branch matching their major and minor version.

2. Create two version bump PRs:

   * One PR should bump the version on the `release-x.y` branch.

     Additionally remove the note at the top of `README.md` about being on the `main` branch.

   * The other PR should bump the version on the `main` branch to the next, unreleased, minor version.

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
