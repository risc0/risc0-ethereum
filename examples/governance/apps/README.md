# Apps

In typical applications, an off-chain app is needed to do two main actions:

* Produce a proof (see [proving options][proving-options]).
* Send a transaction to Ethereum to execute your on-chain logic.

This template provides the `publisher` CLI as an example application to execute these steps.
In a production application, a back-end server or your dApp client may take on this role.

## Publisher

The [`publisher` CLI][publisher], is an example application that produces a proof and publishes it to your app contract.

### Usage

Run the `publisher` with:

```sh
cargo run --bin publisher
```

[proving-options]: https://dev.risczero.com/api/generating-proofs/proving-options
[publisher]: ./src/bin/publisher.rs
