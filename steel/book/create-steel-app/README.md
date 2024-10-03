# create-steel-app

## What does this script do?

The [create-steel-app](create-steel-app) script will allow you to set up the [erc20-counter](https://github.com/risc0/risc0-ethereum/tree/main/examples/erc20-counter) example locally in one command. This example will act as your skeleton project structure for your own application.  Once the script is finished, you can run through a test workflow with either local proving or Bonsai proving. You can also read along at [Core Concepts of Steel](#core-concepts). 

## Dependencies

Make sure to have the following installed:

1. [Rust](https://www.rust-lang.org/tools/install)
2. [Foundry](https://book.getfoundry.sh/getting-started/installation)
3. [cargo-risczero](https://dev.risczero.com/api/zkvm/install)

## Usage

`sh -c "$(curl -fsSL https://raw.githubusercontent.com/sashaaldrick/create-steel-app/main/create-steel-app)"`

The script will automatically detect your current `cargo-risczero` version and use that for the corresponding version of the `erc20-counter` example. You also have the manual choice between between two release versions: [1.0](https://github.com/risc0/risc0-ethereum/tree/release-1.0) and [1.1](https://github.com/risc0/risc0-ethereum/tree/release-1.1).

Once the script is finished running, you should:

```
cd PROJECT_NAME
cargo build
forge build
``` 

After this, you can export the necessary Bonsai environment variables:

```
export BONSAI_API_KEY="YOUR_API_KEY" 
export BONSAI_API_URL="BONSAI_URL" # provided with your api key
```

Note: To request an API key [complete the form here](https://bonsai.xyz/apply).

At this point, you will be able to test against a local deployment by running the provided bash script:

`./test-local-deployment.sh`


