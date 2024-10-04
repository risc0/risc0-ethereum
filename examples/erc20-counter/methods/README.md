# zkVM Methods

This directory contains the [zkVM] portion of your [RISC Zero] application.
This is where you will define one or more [guest programs] to act as a coprocessor to your [on-chain logic].

> In typical use cases, the only code in this directory that you will need to edit is inside [guest/src/bin].


### Writing Guest Code

To learn to write code for the zkVM, we recommend [Guest Code 101].

Examples of what you can do in the guest can be found in the [RISC Zero examples].


### From Guest Code to Binary File

Code in the `methods/guest` directory will be compiled into one or more binaries.

Build configuration for the methods is included in `methods/build.rs`.

Each will have a corresponding image ID, which is a hash identifying the program.


[zkVM]: https://dev.risczero.com/zkvm
[RISC Zero]: https://www.risczero.com/
[guest programs]: https://dev.risczero.com/terminology#guest-program
[on-chain logic]: ../contracts/
[guest/src/bin]: ./guest/src/bin/
[Guest Code 101]: https://dev.risczero.com/api/zkvm/guest-code-101
[RISC Zero examples]: https://github.com/risc0/risc0/tree/main/examples