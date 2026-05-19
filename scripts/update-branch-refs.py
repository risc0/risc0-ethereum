#!/usr/bin/env python3
"""
Branch reference update script for risc0-ethereum release automation.

This script updates branch references from 'main' to a release branch across
GitHub workflows, README files, and other locations.
"""

import argparse
import re
import sys
from pathlib import Path
from typing import List, Tuple


def find_github_workflow_files() -> List[Path]:
    """Find GitHub workflow files that may contain branch references."""
    workflow_dir = Path('.github/workflows')
    if not workflow_dir.exists():
        return []

    return list(workflow_dir.glob('*.yml')) + list(workflow_dir.glob('*.yaml'))


def find_readme_files() -> List[Path]:
    """Find README files that may contain branch references."""
    files = []
    for pattern in ['README.md', '**/README.md']:
        files.extend(Path('.').glob(pattern))
    return files


def update_risc0_monorepo_ref(file_path: Path, release_branch: str, dry_run: bool = False) -> bool:
    """Update RISC0_MONOREPO_REF from 'main' to release branch."""
    if not file_path.exists():
        return False

    try:
        content = file_path.read_text()

        # Pattern to match RISC0_MONOREPO_REF: "main"
        pattern = r'RISC0_MONOREPO_REF:\s*["\']main["\']'
        replacement = f'RISC0_MONOREPO_REF: "{release_branch}"'

        new_content = re.sub(pattern, replacement, content)

        if new_content != content:
            print(f"  {file_path}: RISC0_MONOREPO_REF main -> {release_branch}")
            if not dry_run:
                file_path.write_text(new_content)
            return True

    except Exception as e:
        print(f"Error updating {file_path}: {e}")
        return False

    return False


def update_github_refs(file_path: Path, release_branch: str, dry_run: bool = False) -> bool:
    """Update risc0/risc0-ethereum/refs/heads/main references."""
    if not file_path.exists():
        return False

    try:
        content = file_path.read_text()

        # Pattern to match risc0/risc0-ethereum/refs/heads/main
        pattern = r'risc0/risc0-ethereum/refs/heads/main'
        replacement = f'risc0/risc0-ethereum/refs/heads/{release_branch}'

        new_content = re.sub(pattern, replacement, content)

        if new_content != content:
            print(f"  {file_path}: refs/heads/main -> refs/heads/{release_branch}")
            if not dry_run:
                file_path.write_text(new_content)
            return True

    except Exception as e:
        print(f"Error updating {file_path}: {e}")
        return False

    return False


def update_create_steel_app_urls(file_path: Path, release_branch: str, dry_run: bool = False) -> bool:
    """Update create-steel-app script URLs from main to release branch."""
    if not file_path.exists():
        return False

    try:
        content = file_path.read_text()

        # Pattern to match create-steel-app URLs
        pattern = r'https://raw\.githubusercontent\.com/risc0/risc0-ethereum/refs/heads/main/crates/steel/docs/create-steel-app/create-steel-app'
        replacement = f'https://raw.githubusercontent.com/risc0/risc0-ethereum/refs/heads/{release_branch}/crates/steel/docs/create-steel-app/create-steel-app'

        new_content = re.sub(pattern, replacement, content)

        if new_content != content:
            print(f"  {file_path}: create-steel-app URL main -> {release_branch}")
            if not dry_run:
                file_path.write_text(new_content)
            return True

    except Exception as e:
        print(f"Error updating {file_path}: {e}")
        return False

    return False


def main():
    parser = argparse.ArgumentParser(description='Update branch references for risc0-ethereum release')
    parser.add_argument('release_branch', help='Release branch name (e.g., release-2.1)')
    parser.add_argument('--dry-run', action='store_true', help='Show changes without applying them')

    args = parser.parse_args()

    if args.dry_run:
        print("=== DRY RUN MODE - No changes will be made ===")

    print(f"Updating branch references to: {args.release_branch}")

    changes_made = False

    # Update GitHub workflow files
    print(f"\nUpdating GitHub workflow files:")
    workflow_files = find_github_workflow_files()
    if not workflow_files:
        print("  No workflow files found")
    else:
        for file_path in workflow_files:
            if update_risc0_monorepo_ref(file_path, args.release_branch, args.dry_run):
                changes_made = True

    # Update README files for GitHub refs
    print(f"\nUpdating GitHub refs in README files:")
    readme_files = find_readme_files()
    if not readme_files:
        print("  No README files found")
    else:
        for file_path in readme_files:
            if update_github_refs(file_path, args.release_branch, args.dry_run):
                changes_made = True

    # Update create-steel-app URLs
    print(f"\nUpdating create-steel-app URLs:")
    for file_path in readme_files:
        if update_create_steel_app_urls(file_path, args.release_branch, args.dry_run):
            changes_made = True

    if not changes_made:
        print("\nNo changes needed - branch references are already up to date")
    elif args.dry_run:
        print(f"\nDry run complete. Run without --dry-run to apply changes.")
    else:
        print(f"\nBranch reference update complete -> {args.release_branch}")


if __name__ == '__main__':
    main()