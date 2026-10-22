#!/bin/bash
# Next version preparation script for risc0-ethereum.
#
# This script prepares the main branch for the next development cycle by:
# 1. Bumping versions to next alpha
# 2. Updating contract versions
# 3. Adding new CHANGELOG.md section

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Print functions
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Default values
DRY_RUN=false
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/venv"

# Function to ensure Python environment is set up
ensure_python_env() {
    if [[ ! -d "$VENV_DIR" ]]; then
        print_info "Setting up Python virtual environment..."
        "$SCRIPT_DIR/setup-venv.sh"
    fi
}

# Function to run Python scripts with the virtual environment
run_python() {
    source "$VENV_DIR/bin/activate"
    python3 "$@"
}

# Usage function
usage() {
    cat << EOF
Usage: $0 <next_version> [options]

Arguments:
    next_version        Next development version (e.g., 2.2.0)

Options:
    --dry-run          Show changes without applying them
    --help             Show this help message

Examples:
    $0 2.2.0
    $0 2.2.0 --dry-run

Note: The script will automatically append '-alpha.1' to the provided version.
EOF
}

# Parse arguments
NEXT_VERSION=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --help)
            usage
            exit 0
            ;;
        *)
            if [[ -z "$NEXT_VERSION" ]]; then
                NEXT_VERSION="$1"
            else
                print_error "Unknown argument: $1"
                usage
                exit 1
            fi
            shift
            ;;
    esac
done

# Validate required arguments
if [[ -z "$NEXT_VERSION" ]]; then
    print_error "Next version is required"
    usage
    exit 1
fi

# Validate version format and append alpha suffix
if ! echo "$NEXT_VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
    print_error "Invalid version format. Expected: x.y.z (e.g., 2.2.0)"
    exit 1
fi

NEXT_ALPHA_VERSION="$NEXT_VERSION-alpha.1"

print_info "Preparing next development version: $NEXT_ALPHA_VERSION"

if [[ "$DRY_RUN" == "true" ]]; then
    print_warn "DRY RUN MODE - No changes will be made"
fi

# Check if we're in the right directory
if [[ ! -f "Cargo.toml" ]] || [[ ! -d "contracts" ]]; then
    print_error "This script must be run from the risc0-ethereum repository root"
    exit 1
fi


# Ensure Python environment is ready
ensure_python_env

print_info "Step 1: Updating Cargo.toml versions to $NEXT_ALPHA_VERSION"
if [[ "$DRY_RUN" == "true" ]]; then
    run_python "$SCRIPT_DIR/bump-cargo-versions.py" "$NEXT_ALPHA_VERSION" --mode next-dev --dry-run
else
    run_python "$SCRIPT_DIR/bump-cargo-versions.py" "$NEXT_ALPHA_VERSION" --mode next-dev
fi

print_info "Step 2: Updating contract versions to $NEXT_ALPHA_VERSION"
if [[ "$DRY_RUN" == "true" ]]; then
    run_python "$SCRIPT_DIR/bump-contract-versions.py" "$NEXT_ALPHA_VERSION" --dry-run
else
    run_python "$SCRIPT_DIR/bump-contract-versions.py" "$NEXT_ALPHA_VERSION"
fi

print_info "Step 3: Adding new Unreleased section to CHANGELOG.md"
CHANGELOG_FILE="crates/steel/CHANGELOG.md"
if ! grep -q "## \[Unreleased\]" "$CHANGELOG_FILE"; then
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "[DRY RUN] Would add new Unreleased section to $CHANGELOG_FILE"
    else
        print_info "Adding new Unreleased section to $CHANGELOG_FILE"
        # Find the line with "All notable changes" and add the new section after it
        if [[ "$OSTYPE" == "darwin"* ]]; then
            # macOS
            sed -i '' '/All notable changes to this project will be documented in this file./a\
\
## [Unreleased]\
' "$CHANGELOG_FILE"
        else
            # Linux
            sed -i '/All notable changes to this project will be documented in this file./a\\n## [Unreleased]\n' "$CHANGELOG_FILE"
        fi
    fi
else
    print_info "CHANGELOG.md already has Unreleased section"
fi

print_info "Next version preparation complete!"
print_info ""
print_info "Next steps:"
print_info "1. Review the changes: git status && git diff"
print_info "2. Commit the changes: git add -A && git commit -m 'Prepare next development version $NEXT_ALPHA_VERSION'"
print_info "3. Push to main: git push origin main"
print_info "4. Create a PR for the main branch changes"
