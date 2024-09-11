# Cross-Domain Messaging with Steel
In order for Smart contracts on L1 to interact with smart contracts on L2, Optimism is using a process called "bridging". For more information on Optimism's bridging process, refer to their [documentation](https://docs.optimism.io/builders/app-developers/bridging/messaging).

This example showcases an alternative using the Steel library to do secure and efficient OP-compatible message passing.
It also showcases a *bookmarking block commitment validation* technique, by saving the target block hash to the contract state before generating a Steel proof that targets that specific block. Once the block hash is bookmarked, it can be used later for validation, ensuring that the proof corresponds to the correct blockchain state.

> **Note:** Even though the example specifically targets OP-compatible message passing, most of the code is chain agnostic and can be easily adapted to any EVM-based chain.  

## Key Steps
1. **Send Message from L1:**<br>
Call `L1CrossDomainMessenger::sendMessage(address,bytes)` with the target and the data of message you want to relay to L2.
2. **Bookmark the block hash**<br>
Call `L2CrossDomainMessenger::bookmarkL1Block()` to save the current L1 block hash to the contract state before generating the Steel proof.
3. **Generate Steel Proof:**<br>
Generate a Steel proof verifying the message's inclusion in the L1 state, targeting the bookmarked block.
4. **Relay Message on L2:**<br>
On the L2, call `L2CrossDomainMessenger::relayMessage(bytes,bytes)` with the journal and seal of the Steel proof. This will verify the seal, check the Steel commitment against the bookmarked blocks, and finally relay the message to the target contract.

## Advantages
This method eliminates unnecessary bridging operations, significantly reducing L1 gas costs. The Steel approach also avoids the `OptimismPortal` L1 gas burn, which can vary depending on the usage.

## How to run

- Assure that the `.env` file contains the correct information and potentially deploy the contracts using `forge script --broadcast Deploy`.
- Set `TARGET` and `CALL_DATA` according to the message that you want to pass to the L2.
- Run `cast send $L1_CROSS_DOMAIN_MESSENGER_ADDRESS 'sendMessage(address, bytes)' $TARGET $CALL_DATA)` to submit the message on the L1.
- Create the proof using the `prover` app with the hash of the resulting transaction:
```bash
RUST_LOG=info cargo run -- --tx-hash $SEND_MESSAGE_TX_HASH
```
- Run `cast send $L2_CROSS_DOMAIN_MESSENGER_ADDRESS 'relayMessage(bytes, bytes)' $TARGET $CALL_DATA)` to relay the message on the L2.

The file `e2e-test.sh` contains an examples that performs all those steps in one script.
