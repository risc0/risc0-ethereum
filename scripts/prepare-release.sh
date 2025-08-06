#!/bin/bash
# Release preparation orchestration script for risc0-ethereum.
#
# This script automates the release branch preparation process by:
# 1. Creating a release branch
# 2. Updating versions
# 3. Updating branch references
# 4. Updating dependencies
# 5. Updating other release-specific files

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
RISC0_VERSION="2.0"
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
Usage: $0 <release_version> [options]

Arguments:
    release_version     Version to release (e.g., 2.1.0)

Options:
    --risc0-version     RISC Zero monorepo version to use (default: 2.0)
    --dry-run          Show changes without applying them
    --help             Show this help message

Examples:
    $0 2.1.0
    $0 2.1.0 --risc0-version 2.0 --dry-run
EOF
}

# Parse arguments
RELEASE_VERSION=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --risc0-version)
            RISC0_VERSION="$2"
            shift 2
            ;;
        --help)
            usage
            exit 0
            ;;
        *)
            if [[ -z "$RELEASE_VERSION" ]]; then
                RELEASE_VERSION="$1"
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
if [[ -z "$RELEASE_VERSION" ]]; then
    print_error "Release version is required"
    usage
    exit 1
fi

# Validate release version format
if ! echo "$RELEASE_VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
    print_error "Invalid release version format. Expected: x.y.z (e.g., 2.1.0)"
    exit 1
fi

# Extract major.minor for branch name
MAJOR_MINOR=$(echo "$RELEASE_VERSION" | sed 's/\.[0-9]*$//')
RELEASE_BRANCH="release-$MAJOR_MINOR"

print_info "Preparing release $RELEASE_VERSION"
print_info "Release branch: $RELEASE_BRANCH"
print_info "RISC Zero version: $RISC0_VERSION"

if [[ "$DRY_RUN" == "true" ]]; then
    print_warn "DRY RUN MODE - No changes will be made"
fi

# Check if we're in the right directory
if [[ ! -f "Cargo.toml" ]] || [[ ! -d "contracts" ]]; then
    print_error "This script must be run from the risc0-ethereum repository root"
    exit 1
fi

# Function to run commands with dry-run support
run_cmd() {
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "[DRY RUN] Would run: $*"
    else
        print_info "Running: $*"
        "$@"
    fi
}

# Function to update files with dry-run support
update_file() {
    local file="$1"
    local old_content="$2"
    local new_content="$3"

    if [[ "$DRY_RUN" == "true" ]]; then
        echo "[DRY RUN] Would update $file:"
        echo "  - $old_content"
        echo "  + $new_content"
    else
        print_info "Updating $file"
        if [[ "$OSTYPE" == "darwin"* ]]; then
            # macOS
            sed -i '' "s/$old_content/$new_content/g" "$file"
        else
            # Linux
            sed -i "s/$old_content/$new_content/g" "$file"
        fi
    fi
}

# Ensure Python environment is ready
ensure_python_env

print_info "Step 1: Updating Cargo.toml versions"
if [[ "$DRY_RUN" == "true" ]]; then
    run_python "$SCRIPT_DIR/bump-cargo-versions.py" "$RELEASE_VERSION" --mode release --dry-run
else
    run_python "$SCRIPT_DIR/bump-cargo-versions.py" "$RELEASE_VERSION" --mode release
fi

print_info "Step 2: Updating contract versions"
if [[ "$DRY_RUN" == "true" ]]; then
    run_python "$SCRIPT_DIR/bump-contract-versions.py" "$RELEASE_VERSION" --dry-run
else
    run_python "$SCRIPT_DIR/bump-contract-versions.py" "$RELEASE_VERSION"
fi

print_info "Step 3: Updating branch references"
if [[ "$DRY_RUN" == "true" ]]; then
    run_python "$SCRIPT_DIR/update-branch-refs.py" "$RELEASE_BRANCH" --dry-run
else
    run_python "$SCRIPT_DIR/update-branch-refs.py" "$RELEASE_BRANCH"
fi

print_info "Step 4: Updating risc0 dependencies"
if [[ "$DRY_RUN" == "true" ]]; then
    run_python "$SCRIPT_DIR/update-dependencies.py" "$RISC0_VERSION" --dry-run
else
    run_python "$SCRIPT_DIR/update-dependencies.py" "$RISC0_VERSION"
fi

print_info "Step 5: Updating .gitignore to include Cargo.lock files"
if grep -q "^Cargo.lock$" .gitignore; then
    update_file ".gitignore" "^Cargo.lock$" ""
    update_file ".gitignore" "^# We ignore lock files.*" ""
    update_file ".gitignore" "^# continually track.*" ""
    update_file ".gitignore" "^# tracked, CI will.*" ""
else
    print_info ".gitignore already configured for release"
fi

print_info "Step 6: Updating README.md"
if grep -q "main.*is the development branch" README.md; then
    # Remove the main branch warning
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "[DRY RUN] Would remove main branch warning from README.md"
    else
        print_info "Removing main branch warning from README.md"
        if [[ "$OSTYPE" == "darwin"* ]]; then
            # macOS
            sed -i '' '/> \[!IMPORTANT\]/,/^$/d' README.md
        else
            # Linux
            sed -i '/> \[!IMPORTANT\]/,/^$/d' README.md
        fi
    fi
else
    print_info "README.md already configured for release"
fi

print_info "Step 7: Updating CHANGELOG.md"
if grep -q "## \[Unreleased\]" crates/steel/CHANGELOG.md; then
    update_file "crates/steel/CHANGELOG.md" "## \[Unreleased\]" "## [$RELEASE_VERSION](https://github.com/risc0/risc0-ethereum/releases/tag/v$RELEASE_VERSION)"
else
    print_info "CHANGELOG.md already configured for release"
fi

print_info "Release preparation complete!"
print_info ""
print_info "Next steps:"
print_info "1. Review the changes: git status && git diff"
print_info "2. Commit the changes: git add -A && git commit -m 'Prepare release $RELEASE_VERSION'"
print_info "3. Push the release branch: git push origin $RELEASE_BRANCH"
print_info "4. Create a PR to the release branch"
print_info "5. After the PR is merged, tag the release: git tag v$RELEASE_VERSION"
print_info "6. Create a GitHub release with release notes"
