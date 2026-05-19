#!/usr/bin/env python3
"""
Contract version bump script for risc0-ethereum release automation.

This script updates version strings in Solidity contract files.
"""

import argparse
import re
import sys
from pathlib import Path
from typing import List


def find_contract_files() -> List[Path]:
    """Find contract files that contain version strings."""
    return [
        Path('contracts/src/groth16/RiscZeroGroth16Verifier.sol'),
        Path('contracts/src/RiscZeroSetVerifier.sol')
    ]


def update_contract_version(file_path: Path, new_version: str, dry_run: bool = False) -> bool:
    """Update version string in a Solidity contract file."""
    if not file_path.exists():
        print(f"Warning: {file_path} does not exist")
        return False

    try:
        content = file_path.read_text()

        # Pattern to match version strings in contracts
        pattern = r'string public constant VERSION = "([^"]+)";'

        changes_made = False
        def replace_version(match):
            nonlocal changes_made
            old_version = match.group(1)
            if old_version != new_version:
                print(f"  {file_path}: {old_version} -> {new_version}")
                changes_made = True
                return f'string public constant VERSION = "{new_version}";'
            return match.group(0)

        new_content = re.sub(pattern, replace_version, content)

        if changes_made and not dry_run:
            file_path.write_text(new_content)

        return changes_made

    except Exception as e:
        print(f"Error updating {file_path}: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description='Bump contract version strings for risc0-ethereum release')
    parser.add_argument('version', help='Target version (e.g., 2.1.0)')
    parser.add_argument('--dry-run', action='store_true', help='Show changes without applying them')

    args = parser.parse_args()

    if args.dry_run:
        print("=== DRY RUN MODE - No changes will be made ===")

    print(f"Target version: {args.version}")

    changes_made = False

    # Update contract files
    print(f"\nUpdating contract version strings:")
    contract_files = find_contract_files()
    for file_path in contract_files:
        if update_contract_version(file_path, args.version, args.dry_run):
            changes_made = True

    if not changes_made:
        print("\nNo changes needed - contract versions are already up to date")
    elif args.dry_run:
        print(f"\nDry run complete. Run without --dry-run to apply changes.")
    else:
        print(f"\nContract version bump complete -> {args.version}")


if __name__ == '__main__':
    main()