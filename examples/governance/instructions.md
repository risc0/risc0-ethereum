# Running this example locally

Before starting, make sure to follow the [Installation guide][install-risc0] to have both Rust and RISC Zero's toolchain installed. You'll also need [Foundry][install-foundry] to be installed.

## Setup

From the root of the example repo, run:

```sh
cargo build
forge install
forge build
```

## Running tests

> [!TIP]
> You can adjust the number of fuzz runs for each test case, by changing the `runs` variable in [foundry.toml](./foundry.toml). Higher values gives more confidence in results at the cost of testing speed, see more info at [Fuzz - Foundry Docs][foundry-fuzz-docs].

```sh
RISC0_DEV_MODE=true forge test -vvv
```

Once completed, you should see some output similar to below.

```sh
RISC0_DEV_MODE=true forge test -vvv
[⠊] Compiling...
[⠒] Compiling 87 files with Solc 0.8.23
[⠢] Solc 0.8.23 finished in 4.17s
Compiler run successful with warnings:

Ran 6 tests for contracts/test/BaselineGovernorTest.sol:BaselineGovernorTest
[PASS] testProposalCreation() (gas: 63271)
[PASS] testProposalIDs() (gas: 116812)
[PASS] testQuorumAndExecution() (gas: 198325)
[PASS] testQuorumNotReached() (gas: 139481)
[PASS] testVoting() (gas: 186488)
[PASS] testVotingBySignature() (gas: 271969)
Suite result: ok. 6 passed; 0 failed; 0 skipped; finished in 5.56ms (5.12ms CPU time)

Ran 6 tests for contracts/test/RiscZeroGovernorTest.sol:RiscZeroGovernorTest
[PASS] testProposalCreation() (gas: 85552)
[PASS] testQuorumAndExecution() (gas: 252004)
[PASS] testQuorumNotReached() (gas: 213880)
[PASS] testVerifyAndFinalizeVotes() (gas: 241588)
[PASS] testVoting() (gas: 131218)
[PASS] testVotingBySignature() (gas: 220831)
Suite result: ok. 6 passed; 0 failed; 0 skipped; finished in 5.54ms (6.44ms CPU time)

Ran 2 tests for contracts/test/benchmarks/BenchmarkGovernorsTest.sol:BenchmarkGovernorsTest
[PASS] testFuzz_BaselineWorkflow(uint16) (runs: 10, μ: 120564172, ~: 140488694)
[PASS] testFuzz_RiscZeroWorkflow(uint16) (runs: 10, μ: 86093198, ~: 100443129)
Suite result: ok. 2 passed; 0 failed; 0 skipped; finished in 1.82s (3.46s CPU time)

Ran 3 test suites in 1.83s (1.83s CPU time): 14 tests passed, 0 failed, 0 skipped (14 total tests)
```

## Generating data and gas plots

In the `tests/benchmarks` folder, there are two Python files. They both handle data written to a csv from the [BenchmarkGovernorsTest.sol](./tests/benchmarks/BenchmarkGovernorsTest.sol) file using Foundry's writing data cheatcode.

- [print_gas_data.py]: pretty prints data from `gas_data.csv`
- [plot_gas_data.py]: generates a matplotlib plot of gas usage in .png format: [gas_data_comparison.png]

To set up your python environment, it is recommend to use a virtual environment such as `venv` or `conda`.

### Using venv

Change into the benchmarks directory with:

```sh
cd tests/benchmarks
```

Create the virtual environment with:

```sh
python -m venv governance
```

Activate the virtual environment with:

```sh
source governance/bin/activate
```

Install the requirements with:

```sh
pip install -r requirements.txt
```

### Using conda

Change into the benchmarks directory with:

```sh
cd tests/benchmarks
```

Create the virtual environment with:

```sh
conda env create -f environment.yml
```

Activate the virtual environment with:

```sh
conda activate governance
```

## Running the print/plot python files

Change into the benchmarks directory with:

```sh
cd tests/benchmarks
```

Make sure the correct environment is activated and all the dependencies installed either with [venv](#using-venv) or an alternative like [conda](#using-conda).

The data is only generated when the tests are run, see [running tests].

```sh
python print_gas_data.py
```

```sh
python plot_gas_data.py
```

The plot generated will be saved as [gas_data_comparison.png]:

![Gas Data Comparison](contracts/test/benchmarks/gas_data_comparison.png)

[install-foundry]: https://book.getfoundry.sh/getting-started/installation
[foundry-fuzz-docs]: https://book.getfoundry.sh/reference/config/testing#fuzz
[gas_data_comparison.png]: ./contracts/test/benchmarks/gas_data_comparison.png
[install-risc0]: https://dev.risczero.com/api/zkvm/install
[print_gas_data.py]: ./contracts/test/benchmarks/print_gas_data.py
[plot_gas_data.py]: ./contracts/test/benchmarks/plot_gas_data.py
[running tests]: #running-tests

