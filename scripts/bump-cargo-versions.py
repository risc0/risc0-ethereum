#!/usr/bin/env python3
"""
Cargo version bump script for risc0-ethereum release automation.

This script updates versions across all workspace Cargo.toml files.
Supports both release mode (x.y.z) and next development mode (x.y+1.0-alpha.1).
"""

import argparse
import re
import sys
import toml
from pathlib import Path
from typing import List, Tuple, Optional


def parse_version(version_str: str) -> Tuple[int, int, int, Optional[str]]:
    """Parse semantic version string into components."""
    pattern = r'^(\d+)\.(\d+)\.(\d+)(?:-(.+))?$'
    match = re.match(pattern, version_str)
    if not match:
        raise ValueError(f"Invalid version format: {version_str}")

    major, minor, patch, prerelease = match.groups()
    return int(major), int(minor), int(patch), prerelease


def format_version(major: int, minor: int, patch: int, prerelease: Optional[str] = None) -> str:
    """Format version components back to string."""
    version = f"{major}.{minor}.{patch}"
    if prerelease:
        version += f"-{prerelease}"
    return version


def get_next_release_version(current_version: str) -> str:
    """Convert alpha version to release version (remove prerelease suffix)."""
    major, minor, patch, prerelease = parse_version(current_version)
    if prerelease and 'alpha' in prerelease:
        # Remove alpha suffix for release
        return format_version(major, minor, patch)
    else:
        # Already a release version, just return as-is
        return current_version


def get_next_dev_version(current_version: str) -> str:
    """Get next development version (increment minor, set patch to 0, add alpha.1)."""
    major, minor, patch, prerelease = parse_version(current_version)
    # For next dev version, increment minor and reset patch
    return format_version(major, minor + 1, 0, "alpha.1")


def find_cargo_toml_files() -> List[Path]:
    """Find all Cargo.toml files that need version updates."""
    root = Path('.')

    # Use the grep command from RELEASE.md to find files
    import subprocess
    result = subprocess.run([
        'grep', '-rl', '^version = "', '--include=Cargo.toml',
        '--exclude-dir=./lib', '--exclude-dir=./examples',
        '--exclude-dir=./crates/ffi/guests', '--exclude-dir=./target', '.'
    ], capture_output=True, text=True, cwd=root)

    if result.returncode != 0:
        return []

    files = [Path(f.strip()) for f in result.stdout.strip().split('\n') if f.strip()]
    return [f for f in files if f.exists()]


def update_cargo_toml(file_path: Path, new_version: str, dry_run: bool = False) -> bool:
    """Update version in a Cargo.toml file."""
    if not file_path.exists():
        print(f"Warning: {file_path} does not exist")
        return False

    try:
        content = file_path.read_text()
        data = toml.loads(content)

        # Check if this file has a version field
        if 'package' in data and 'version' in data['package']:
            old_version = data['package']['version']
            if old_version != new_version:
                print(f"  {file_path}: {old_version} -> {new_version}")
                if not dry_run:
                    data['package']['version'] = new_version
                    file_path.write_text(toml.dumps(data))
                return True

        # Check workspace version
        if 'workspace' in data and 'package' in data['workspace'] and 'version' in data['workspace']['package']:
            old_version = data['workspace']['package']['version']
            if old_version != new_version:
                print(f"  {file_path} (workspace): {old_version} -> {new_version}")
                if not dry_run:
                    data['workspace']['package']['version'] = new_version
                    file_path.write_text(toml.dumps(data))
                return True

    except Exception as e:
        print(f"Error updating {file_path}: {e}")
        return False

    return False


def main():
    parser = argparse.ArgumentParser(description='Bump Cargo.toml versions for risc0-ethereum release')
    parser.add_argument('version', help='Target version (e.g., 2.1.0 or auto)')
    parser.add_argument('--mode', choices=['release', 'next-dev'], required=True,
                       help='release: prepare for release, next-dev: prepare for next development cycle')
    parser.add_argument('--dry-run', action='store_true', help='Show changes without applying them')

    args = parser.parse_args()

    # Read current version from workspace Cargo.toml
    workspace_cargo = Path('Cargo.toml')
    if not workspace_cargo.exists():
        print("Error: Cargo.toml not found in current directory")
        sys.exit(1)

    try:
        workspace_data = toml.loads(workspace_cargo.read_text())
        current_version = workspace_data['workspace']['package']['version']
        print(f"Current version: {current_version}")
    except Exception as e:
        print(f"Error reading workspace Cargo.toml: {e}")
        sys.exit(1)

    # Determine target version
    if args.version == 'auto':
        if args.mode == 'release':
            target_version = get_next_release_version(current_version)
        else:  # next-dev
            target_version = get_next_dev_version(current_version)
    else:
        target_version = args.version

    print(f"Target version: {target_version}")

    if args.dry_run:
        print("\n=== DRY RUN MODE - No changes will be made ===")

    # Validate target version format
    try:
        parse_version(target_version)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    changes_made = False

    # Update Cargo.toml files
    print(f"\nUpdating Cargo.toml files:")
    cargo_files = find_cargo_toml_files()
    if not cargo_files:
        print("No Cargo.toml files found")
    else:
        for file_path in cargo_files:
            if update_cargo_toml(file_path, target_version, args.dry_run):
                changes_made = True

    if not changes_made:
        print("\nNo changes needed - versions are already up to date")
    elif args.dry_run:
        print(f"\nDry run complete. Run without --dry-run to apply changes.")
    else:
        print(f"\nCargo version bump complete: {current_version} -> {target_version}")


if __name__ == '__main__':
    main()