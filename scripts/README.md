# Release Automation Scripts

This directory contains scripts to automate the risc0-ethereum release process as described in [RELEASE.md](../RELEASE.md).

## Quick Start

### Prerequisites

- Python 3.7+
- Git
- Bash

### Setup

1. Set up the Python environment:
```bash
scripts/setup-venv.sh
```

2. Run a release preparation (dry-run first!):
```bash
# Prepare release 2.1.0 (dry run)
scripts/prepare-release.sh 2.1.0 --dry-run

# Actually run it
scripts/prepare-release.sh 2.1.0
```

3. Prepare next development version:
```bash
# Prepare next dev version 2.2.0-alpha.1 (dry run)
scripts/prepare-next-version.sh 2.2.0 --dry-run

# Actually run it
scripts/prepare-next-version.sh 2.2.0
```

## Main Orchestration Scripts

### `prepare-release.sh`
Automates the complete release branch preparation process.

**Usage:**
```bash
scripts/prepare-release.sh <release_version> [options]

Arguments:
  release_version     Version to release (e.g., 2.1.0)

Options:
  --risc0-version     RISC Zero monorepo version to use (default: 2.0)
  --dry-run          Show changes without applying them
  --help             Show help message

Examples:
  scripts/prepare-release.sh 2.1.0
  scripts/prepare-release.sh 2.1.0 --risc0-version 2.0 --dry-run
```

**What it does:**
1. Creates release branch (e.g., `release-2.1`)
2. Updates all Cargo.toml versions to release version
3. Updates contract version strings
4. Updates branch references from `main` to release branch
5. Converts risc0 git dependencies to version dependencies
6. Updates .gitignore to include Cargo.lock files
7. Removes main branch warning from README.md
8. Updates CHANGELOG.md to mark current version as released

### `prepare-next-version.sh`
Prepares the main branch for the next development cycle.

**Usage:**
```bash
scripts/prepare-next-version.sh <next_version> [options]

Arguments:
  next_version        Next development version (e.g., 2.2.0)
                     Script automatically appends '-alpha.1'

Options:
  --dry-run          Show changes without applying them
  --help             Show help message

Examples:
  scripts/prepare-next-version.sh 2.2.0
  scripts/prepare-next-version.sh 2.2.0 --dry-run
```

**What it does:**
1. Updates all Cargo.toml versions to next alpha version
2. Updates contract version strings to next alpha version
3. Adds new "Unreleased" section to CHANGELOG.md