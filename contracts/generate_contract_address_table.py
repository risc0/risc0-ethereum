# Copyright 2024 RISC Zero, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from urllib.parse import urljoin
import tomllib
import sys

def load_toml(file_path):
    """Load the TOML file from the given path."""

    with open(file_path, "rb") as f:
        return tomllib.load(f)

class Link:
    def __init__(self, tag, url):
        self.tag = tag
        self.url = url

def generate_table_for_chain(chain_name, chain_data, version):
    """Generate markdown content for a specific blockchain."""

    chain_id = chain_data['id']

    links = []
    etherscan_url = chain_data['etherscan-url']

    md_content = f"### {chain_data['name']} ({chain_id})\n\n"
    md_content += "| Contract                     | Address   |\n"
    md_content += "| ---------------------------- | --------- |\n"

    # Add timelock controller and router
    # NOTE: TimelockController and RiscZeroVerifierRouter may not be deployed to all chains.
    timelock_addr = chain_data['timelock-controller']
    router_addr = chain_data['router']

    # The router is the contract devs are most likely to interact with, so it is first.
    md_content += f"| [RiscZeroVerifierRouter][router-src] | [`{router_addr}`][router-{chain_id}-etherscan] |\n"
    links.append(Link(f"router-{chain_id}-etherscan", urljoin(etherscan_url, f"address/{router_addr}#code")))

    # Add verifiers that match the version
    if "verifiers" in chain_data:
        for verifier in chain_data["verifiers"]:
            if verifier.get("version") == version:
                verifier_addr = verifier['verifier']
                estop_addr = verifier['estop']

                md_content += f"| [RiscZeroGroth16Verifier][verifier-src]    | [`{verifier_addr}`][verifier-{chain_id}-etherscan] |\n"
                md_content += f"| [RiscZeroVerifierEmergencyStop][estop-src] | [`{estop_addr}`][estop-{chain_id}-etherscan] |\n"

                links.append(Link(f"estop-{chain_id}-etherscan", urljoin(etherscan_url, f"address/{estop_addr}#code")))
                links.append(Link(f"verifier-{chain_id}-etherscan", urljoin(etherscan_url, f"address/{verifier_addr}#code")))

                break

    # TimelockController is the contract devs are least-likely to interact with, so it is last.
    md_content += f"| TimelockController                         | [`{timelock_addr}`][timelock-{chain_id}-etherscan] |\n\n"
    links.append(Link(f"timelock-{chain_id}-etherscan", urljoin(etherscan_url, f"address/{timelock_addr}#code")))

    # Add the links section
    for link in links:
        md_content += f"[{link.tag}]: {link.url}\n"

    return md_content

def main(toml_file, version):
    # Load the TOML configuration
    config = load_toml(toml_file)

    # Initialize an empty markdown output
    all_md_content = "<!-- GENERATED CONTENT BEGIN -->\n\n"

    # Process each chain
    for chain_key, chain_data in config.get("chains", {}).items():
        # Skip generation of the table chains where deployment did not succeed.
        # See notes in deployment.toml.
        if chain_key in ("polygon-zkevm-testnet", "linea-sepolia"):
            continue

        # Generate markdown content for the chain
        md_content = generate_table_for_chain(chain_key, chain_data, version)
        all_md_content += md_content + "\n<br/>\n\n"

    all_md_content += f"[router-src]: https://github.com/risc0/risc0-ethereum/tree/v{version}/contracts/src/RiscZeroVerifierRouter.sol\n"
    all_md_content += f"[verifier-src]: https://github.com/risc0/risc0-ethereum/tree/v{version}/contracts/src/groth16/RiscZeroGroth16Verifier.sol\n"
    all_md_content += f"[estop-src]: https://github.com/risc0/risc0-ethereum/tree/v{version}/contracts/src/groth16/RiscZeroVerifierEmergencyStop.sol\n"

    all_md_content += "\n<!-- GENERATED CONTENT END-->"

    # Output the entire markdown content to stdout
    print(all_md_content)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python generate_md.py <path_to_toml_file> <version>")
        sys.exit(1)

    toml_file = sys.argv[1]
    version = sys.argv[2]

    main(toml_file, version)
