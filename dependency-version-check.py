import os
import toml
from collections import defaultdict

# List of folders to exclude
EXCLUDE_FOLDERS = ['target']

def find_cargo_toml_files(root_dir):
    cargo_toml_files = []
    for dirpath, _, filenames in os.walk(root_dir):
        if any(excluded in dirpath for excluded in EXCLUDE_FOLDERS):
            continue
        for filename in filenames:
            if filename == 'Cargo.toml':
                cargo_toml_files.append(os.path.join(dirpath, filename))
    return cargo_toml_files

def get_version_string(version_info):
    if isinstance(version_info, str):
        return version_info
    elif isinstance(version_info, dict):
        if 'workspace' in version_info and version_info['workspace'] is True:
            return 'workspace'
        if 'version' in version_info:
            return version_info['version']
    return str(version_info)

def get_dependencies_versions(cargo_toml_path, dependencies):
    with open(cargo_toml_path, 'r') as file:
        cargo_toml_content = toml.load(file)

    versions = {}
    for dep in dependencies:
        if 'dependencies' in cargo_toml_content and dep in cargo_toml_content['dependencies']:
            versions[dep] = get_version_string(cargo_toml_content['dependencies'][dep])
        if 'dev-dependencies' in cargo_toml_content and dep in cargo_toml_content['dev-dependencies']:
            versions[dep] = get_version_string(cargo_toml_content['dev-dependencies'][dep])
        if 'build-dependencies' in cargo_toml_content and dep in cargo_toml_content['build-dependencies']:
            versions[dep] = get_version_string(cargo_toml_content['build-dependencies'][dep])
    return versions

def check_versions_consistency(root_dir, dependencies):
    cargo_toml_files = find_cargo_toml_files(root_dir)
    all_versions = {dep: defaultdict(set) for dep in dependencies}

    for cargo_toml_path in cargo_toml_files:
        versions = get_dependencies_versions(cargo_toml_path, dependencies)
        for dep, version in versions.items():
            all_versions[dep][version].add(cargo_toml_path)

    inconsistent_deps = {dep: versions for dep, versions in all_versions.items() if len(versions) > 1 and 'workspace' not in versions}
    return inconsistent_deps

def main():
    root_dir = './'
    dependencies_to_check = [
        'risc0-zkvm', 
        'risc0-build', 
        'risc0-zkp',
        'risc0-build-ethereum',
        'risc0-ethereum-contracts',
        'risc0-steel',
        'risc0-forge-ffi'
        ]

    inconsistent_dependencies = check_versions_consistency(root_dir, dependencies_to_check)

    if inconsistent_dependencies:
        print("Inconsistent dependencies found:")
        for dep, versions in inconsistent_dependencies.items():
            print(f"Dependency '{dep}' has multiple versions:")
            for version, paths in versions.items():
                print(f"  Version '{version}' found in:")
                for path in paths:
                    print(f"    - {path}")
    else:
        print("All dependencies are consistent.")

if __name__ == "__main__":
    main()
