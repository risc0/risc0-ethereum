.POSIX:
.SILENT:

.PHONY: devnet-up devnet-down check-deps clean all

# Variables
ANVIL_PORT = 8545
ANVIL_BLOCK_TIME = 1
RPC_URL := http://localhost:$(ANVIL_PORT)
DEPLOYER_PUBLIC_KEY := 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
DEPLOYER_PRIVATE_KEY := 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
ADMIN_ADDRESS := 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
CHAIN_KEY := anvil

LOGS_DIR = logs
PID_FILE = $(LOGS_DIR)/devnet.pid

all: devnet-up

# Check that required dependencies are installed
check-deps:
	for cmd in forge anvil jq; do \
		command -v $$cmd >/dev/null 2>&1 || { echo "Error: $$cmd is not installed."; exit 1; }; \
	done

devnet-up: check-deps
	mkdir -p $(LOGS_DIR)
	echo "Building contracts..."
	forge build || { echo "Failed to build contracts"; $(MAKE) devnet-down; exit 1; }
	# Check if Anvil is already running
	if nc -z localhost $(ANVIL_PORT); then \
		echo "Anvil is already running on port $(ANVIL_PORT). Reusing existing instance."; \
	else \
		echo "Starting Anvil..."; \
		anvil -b $(ANVIL_BLOCK_TIME) > $(LOGS_DIR)/anvil.txt 2>&1 & echo $$! >> $(PID_FILE); \
		sleep 5; \
	fi
	echo "Deploying contracts..."
	{ \
		unset VERIFIER_ESTOP; \
		unset VERIFIER_ROUTER; \
		unset TIMELOCK_CONTROLLER; \
		unset VERIFIER; \
		unset VERIFIER_SELECTOR; \
		MIN_DELAY=1 PROPOSER=$(ADMIN_ADDRESS) EXECUTOR=$(ADMIN_ADDRESS) bash contracts/script/manage DeployTimelockRouter --broadcast && \
		TIMELOCK_CONTROLLER=$$(jq -re '.transactions[] | select(.contractName == "TimelockController") | .contractAddress' ./broadcast/Manage.s.sol/31337/run-latest.json) && \
		VERIFIER_ROUTER=$$(jq -re '.transactions[] | select(.contractName == "RiscZeroVerifierRouter") | .contractAddress' ./broadcast/Manage.s.sol/31337/run-latest.json) && \
		export TIMELOCK_CONTROLLER=$$TIMELOCK_CONTROLLER && \
		export VERIFIER_ROUTER=$$VERIFIER_ROUTER && \
		CHAIN_KEY=$(CHAIN_KEY) VERIFIER_ESTOP_OWNER=$(ADMIN_ADDRESS) bash contracts/script/manage DeployEstopVerifier --broadcast && \
		VERIFIER_ESTOP=$$(jq -re '.transactions[] | select(.contractName == "RiscZeroVerifierEmergencyStop") | .contractAddress' ./broadcast/Manage.s.sol/31337/run-latest.json) && \
		VERIFIER=$$(jq -re '.transactions[] | select(.contractName == "RiscZeroGroth16Verifier") | .contractAddress' ./broadcast/Manage.s.sol/31337/run-latest.json) && \
		VERIFIER_SELECTOR=$$(cast call --rpc-url $(RPC_URL) $$VERIFIER 'SELECTOR()' | cut -c 1-10) && \
		export VERIFIER_ESTOP=$$VERIFIER_ESTOP && \
		export VERIFIER=$$VERIFIER && \
		export VERIFIER_SELECTOR=$$VERIFIER_SELECTOR && \
		bash contracts/script/manage ScheduleAddVerifier --broadcast && \
		sleep 5 && \
		bash contracts/script/manage FinishAddVerifier --broadcast && \
		echo "Devnet is up and running!" && \
		echo "TimelockController: $$TIMELOCK_CONTROLLER" && \
		echo "RiscZeroVerifierRouter: $$VERIFIER_ROUTER" && \
		echo "RiscZeroVerifierEmergencyStop: $$VERIFIER_ESTOP" && \
		echo "RiscZeroGroth16Verifier: $$VERIFIER" && \
		echo "Selector: $$VERIFIER_SELECTOR"; \
	} || { echo "Failed to deploy contracts"; $(MAKE) devnet-down; exit 1; }

devnet-down:
	echo "Bringing down all services..."
	if [ -f $(PID_FILE) ]; then \
		while read pid; do \
			kill $$pid 2>/dev/null || true; \
		done < $(PID_FILE); \
		rm $(PID_FILE); \
	fi
	echo "Devnet stopped."

clean: devnet-down
	echo "Cleaning up..."
	rm -rf $(LOGS_DIR) ./broadcast
	forge clean
	echo "Cleanup complete."
