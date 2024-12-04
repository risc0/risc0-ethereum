# create-steel-app

## What does this script do?

The [create-steel-app] script will allow you to set up the [erc20-counter] example locally in one command. This example will act as your skeleton project structure for your own application. Once the script is finished, you can run through a test workflow with either local proving or Bonsai proving. You can also learn more about Steel by reading the [documentation].

## Dependencies

Make sure to have the following installed:

1. [Rust]
2. [Foundry]
3. [cargo-risczero]

## Usage

```sh
sh <(curl -fsSL https://raw.githubusercontent.com/risc0/risc0-ethereum/refs/heads/main/steel/docs/create-steel-app/create-steel-app)
```

The script will automatically detect your current `cargo-risczero` version and use that for the corresponding version of the `erc20-counter` example. You also have the manual choice between two release versions: [1.0] and [1.1].

Once the script is finished running, you should:

```console
cd PROJECT_NAME
cargo build
forge build
```

After this, you can export the necessary Bonsai environment variables if you'd like to use Bonsai. Otherwise, local proving will be used:

```console
export BONSAI_API_KEY="YOUR_API_KEY" 
export BONSAI_API_URL="BONSAI_URL" # provided with your api key
```

_Note: To request an API key [complete the form here]_.

At this point, you will be able to test against a local deployment by running the provided bash script:

`./test-local-deployment.sh`

[create-steel-app]: create-steel-app
[erc20-counter]: https://github.com/risc0/risc0-ethereum/tree/main/examples/erc20-counter
[documentation]: ../../README.md#documentation
[Rust]: https://www.rust-lang.org/tools/install
[Foundry]: https://book.getfoundry.sh/getting-started/installation
[cargo-risczero]: https://dev.risczero.com/api/zkvm/install
[1.0]: https://github.com/risc0/risc0-ethereum/tree/release-1.0
[1.1]: https://github.com/risc0/risc0-ethereum/tree/release-1.1
