# *What is Steel*

## *Steel: Introducing Verifiable Asynchronous Calls to Solidity*

Steel introduces verifiable async calls to Solidity execution. You may be familiar with the concept of asynchronous (async) calls in Javascript. A fundamental operation of the web is to request data from an external source, or endpoint, and wait for it to be returned. Once returned, that data can be, for example, displayed to the end user. Specifically, there is a specific term used to manage async operations in Javascript: a *Promise*. Promises are objects which *promise* to produce a single value in the future.

Let's take a simple and common use case, fetching data from an API:

```javascript
let response = await fetch("https://example.com");
console.log(await response2.text())
```

`fetch()` returns a `Promise` (specifically a `Promise<Response>`) and when that promise is resolved and saved to the `response` variable, we can then manipulate this data and use it for the intended purpose.

In Solidity, calls to external contracts, such as to check an ERC20 balance, are synchronous; they happen immediately in the same transaction and the execution waits for the call to complete before moving on. This operation in the EVM is known as an Storage Load (opcode [SLOAD](https://www.evm.codes/#54)) and it is not cheap \- costing 2100 gas (for cold retrievals with no access list). With multiple `SLOAD`s, these gas costs become significant; further limiting the already limited compute available.

You can use Steel to asynchronously request a zkVM "endpoint" to carry out some computation for you and return the output, together with a cryptographically secured promise, a ZK-proof. This ZK-proof can be verified and you can be sure that this computation was carried out as expected and produced the corresponding output. Based on the validity of this proof, you can take these outputs and conditionally update state and continue execution.
