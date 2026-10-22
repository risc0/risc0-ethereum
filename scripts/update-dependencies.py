#!/usr/bin/env python3
"""
Dependency update script for risc0-ethereum release automation.

This script updates risc0 monorepo dependencies from git references to published versions,
and runs cargo update in all workspaces.
"""

import argparse
import subprocess
import sys
import toml
from pathlib import Path
from typing import List, Dict, Any


def find_workspace_cargo_files() -> List[Path]:
    """Find all workspace root Cargo.toml files."""
    # Use the grep command from RELEASE.md to find workspace files
    result = subprocess.run([
        'grep', '-rl', '--include=Cargo.toml', r'\[workspace\]',
        '--exclude-dir=./lib', '.'
    ], capture_output=True, text=True)

    if result.returncode != 0:
        return []

    files = [Path(f.strip()) for f in result.stdout.strip().split('\n') if f.strip()]
    return [f for f in files if f.exists()]


def update_risc0_dependencies(file_path: Path, risc0_version: str, dry_run: bool = False) -> bool:
    """Update risc0 git dependencies to version dependencies in a Cargo.toml file."""
    if not file_path.exists():
        return False

    try:
        content = file_path.read_text()
        data = toml.loads(content)

        changes_made = False

        # Check workspace dependencies
        if 'workspace' in data and 'dependencies' in data['workspace']:
            deps = data['workspace']['dependencies']
            for dep_name, dep_info in deps.items():
                if dep_name.startswith('risc0-') and isinstance(dep_info, dict):
                    # Check if it's a git dependency pointing to risc0 repo
                    if 'git' in dep_info and 'risc0/risc0' in dep_info['git']:
                        print(f"  {file_path}: {dep_name} git -> version {risc0_version}")
                        if not dry_run:
                            # Remove git and branch, add version
                            dep_info.pop('git', None)
                            dep_info.pop('branch', None)
                            dep_info['version'] = risc0_version
                        changes_made = True

        # Check regular dependencies
        if 'dependencies' in data:
            deps = data['dependencies']
            for dep_name, dep_info in deps.items():
                if dep_name.startswith('risc0-') and isinstance(dep_info, dict):
                    # Check if it's a git dependency pointing to risc0 repo
                    if 'git' in dep_info and 'risc0/risc0' in dep_info['git']:
                        print(f"  {file_path}: {dep_name} git -> version {risc0_version}")
                        if not dry_run:
                            # Remove git and branch, add version
                            dep_info.pop('git', None)
                            dep_info.pop('branch', None)
                            dep_info['version'] = risc0_version
                        changes_made = True

        if changes_made and not dry_run:
            file_path.write_text(toml.dumps(data))

        return changes_made

    except Exception as e:
        print(f"Error updating {file_path}: {e}")
        return False


def run_cargo_update(workspace_dir: Path, dry_run: bool = False) -> bool:
    """Run cargo update in a workspace directory."""
    if not workspace_dir.exists():
        return False

    cargo_toml = workspace_dir / 'Cargo.toml'
    if not cargo_toml.exists():
        return False

    print(f"  Running cargo update in {workspace_dir}")

    if dry_run:
        print(f"    (dry run - would run: cargo update --manifest-path {cargo_toml})")
        return True

    try:
        result = subprocess.run([
            'cargo', 'update', '--manifest-path', str(cargo_toml)
        ], capture_output=True, text=True, cwd=workspace_dir)

        if result.returncode != 0:
            print(f"    Error running cargo update: {result.stderr}")
            return False

        if result.stdout.strip():
            print(f"    {result.stdout.strip()}")

        return True

    except Exception as e:
        print(f"    Error running cargo update: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description='Update risc0 dependencies for risc0-ethereum release')
    parser.add_argument('risc0_version', help='RISC Zero version to use (e.g., 2.0)')
    parser.add_argument('--dry-run', action='store_true', help='Show changes without applying them')

    args = parser.parse_args()

    if args.dry_run:
        print("=== DRY RUN MODE - No changes will be made ===")

    print(f"Updating risc0 dependencies to version: {args.risc0_version}")

    changes_made = False

    # Find all workspace Cargo.toml files
    print(f"\nFinding workspace Cargo.toml files:")
    workspace_files = find_workspace_cargo_files()
    if not workspace_files:
        print("  No workspace files found")
        return

    for file_path in workspace_files:
        print(f"  Found workspace: {file_path}")

    # Update dependencies in workspace files
    print(f"\nUpdating risc0 dependencies:")
    for file_path in workspace_files:
        if update_risc0_dependencies(file_path, args.risc0_version, args.dry_run):
            changes_made = True

    # Run cargo update in each workspace
    print(f"\nRunning cargo update in workspaces:")
    for file_path in workspace_files:
        workspace_dir = file_path.parent
        run_cargo_update(workspace_dir, args.dry_run)

    if not changes_made:
        print("\nNo dependency changes needed")
    elif args.dry_run:
        print(f"\nDry run complete. Run without --dry-run to apply changes.")
    else:
        print(f"\nDependency update complete -> risc0 {args.risc0_version}")


if __name__ == '__main__':
    main()