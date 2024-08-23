# Cross-Domain Messaging with Steel
In order for Smart contracts on L1 to interact with smart contracts on L2, Optimism is using a process called "bridging". For more information on Optimism's bridging process, refer to their [documentation](https://docs.optimism.io/builders/app-developers/bridging/messaging).

This example showcases an alternative using the Steel library to do secure and efficient OP-compatible message passing.
It also showcases a *bookmarking block commitment validation* technique, by saving the target block hash to the contract state before generating a Steel proof that targets that specific block. Once the block hash is bookmarked, it can be used later for validation, ensuring that the proof corresponds to the correct blockchain state.

> **Note:** Even though the example specifically targets OP-compatible message passing, most of the code is chain agnostic and can be easily adapted to any EVM-based chain.  

## Key Steps
1. **Send Message from L1:**<br>
Call `L1CrossDomainMessenger.sendMessage` with the message you want to relay to L2.
2. **Generate Steel Proof:**<br> Generate a Steel proof verifying the message's inclusion in the L1 state.
3. **Relay Message on L2:**<br> On L2, use `L2CrossDomainMessenger.relayMessage` with the message and Steel proof. Upon successful verification, the message will be relayed to the target contract, ensuring its validity as an L1 message.

## Advantages
This method eliminates unnecessary bridging operations, significantly reducing L1 gas costs. The Steel approach also avoids the `OptimismPortal` L1 gas burn, which can vary depending on the usage.

## How to run
We deployed this example on Sepolia and OP-Sepolia. You can export:

```bash
L1_WALLET_PRIVATE_KEY="YOUR_SEPOLIA_WALLET_PRIVATE_KEY"
L2_WALLET_PRIVATE_KEY="YOUR_OP_SEPOLIA_WALLET_PRIVATE_KEY"
```

and finally run

```bash
RISC0_DEV_MODE=1 RUST_LOG=info cargo run
```