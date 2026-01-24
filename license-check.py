#!/usr/bin/env python

import sys
from pathlib import Path
import subprocess
import argparse
import re

PUBLIC_HEADER = '''
// Copyright {YEAR} RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
'''.strip()

PUBLIC_HEADER_RE = re.compile(
    "^"
    + PUBLIC_HEADER.replace("(", "\\(")
    .replace(")", "\\)")
    .replace("{YEAR}", "(?P<year>[0-9]+)"),
)

EXTENSIONS = [
    '.cpp',
    '.h',
    '.rs',
    '.sol',
]

SKIP_DIRS = [
    # Groth16 verifier implementation uses circom generated code under GPL3.
    str(Path.cwd()) + "/contracts/src/groth16",
    str(Path.cwd()) + "/contracts/src/test/utils/Strings2.sol",
    str(Path.cwd()) + "/examples/erc20-counter/contracts/ERC20.sol",
]

def check_header(expected_year, lines_actual):
    for (expected, actual) in zip(PUBLIC_HEADER.splitlines(), lines_actual):
        expected = expected.replace('{YEAR}', expected_year)
        if expected != actual:
            return (expected, actual)
    return None


def fix_file(file_obj, file_contents, start, end, insert):
    file_contents = file_contents[:start] + insert + file_contents[end:]
    file_obj.seek(0)
    file_obj.truncate()
    file_obj.write(file_contents)


def is_comment_line(line: str) -> bool:
    return line.strip().startswith("//")


def is_probably_license_block(lines: list[str]) -> bool:
    license_keywords = ["copyright", "license", "spdx", "apache", "mit"]
    text = "\n".join(lines).lower()
    return any(kw in text for kw in license_keywords)


def find_license_block(file_contents: str) -> tuple[int, int] | None:
    """Return (char_start, char_end) span of a license block, or None if not found."""
    lines = file_contents.splitlines(keepends=True)

    license_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped == "" or is_comment_line(stripped):
            license_lines.append(line)
        else:
            break

    if license_lines and is_probably_license_block(license_lines):
        char_start = 0
        char_end = sum(len(line) for line in license_lines)
        return char_start, char_end

    return None


def check_file(root, file, fix):
    cmd = ['git', 'log', '-1', '--format=%ad', '--date=format:%Y', '--', file]
    expected_year = subprocess.check_output(cmd, encoding='UTF-8').strip()
    rel_path = file.relative_to(root)

    with open(file, "r+") as file_obj:
        file_contents = file_obj.read()
        match = PUBLIC_HEADER_RE.match(file_contents)

        if match:
            actual_year = match.group("year")
            if actual_year != expected_year:
                print(f'{rel_path}: invalid header!')
                print(f'license has wrong year {actual_year}, expected {expected_year}')
                if fix:
                    print(f'fixing {rel_path}')
                    start, end = match.span(1)
                    fix_file(file_obj, file_contents, start, end, expected_year)
                else:
                    return 1
        else:
            lines = file_contents.splitlines()
            result = check_header(expected_year, lines)
            if result:
                print(f'{rel_path}: invalid header!')
                print(f'  expected: {result[0]}')
                print(f'    actual: {result[1]}')
                if fix:
                    print(f'fixing {rel_path}')
                    new_header = PUBLIC_HEADER.replace("{YEAR}", expected_year) + "\n\n"
                    span = find_license_block(file_contents)
                    if span:
                        start, end = span
                        fix_file(file_obj, file_contents, start, end, new_header)
                    else:
                        fix_file(file_obj, file_contents, 0, 0, new_header)
                else:
                    return 1

    return 0


def repo_root():
    """Return an absolute Path to the repo root"""
    cmd = ["git", "rev-parse", "--show-toplevel"]
    return Path(subprocess.check_output(cmd, encoding='UTF-8').strip())


def tracked_files():
    """Yield all file paths tracked by git"""
    cmd = ["git", "ls-tree", "--full-tree", "--name-only", "-r", "HEAD"]
    tree = subprocess.check_output(cmd, encoding='UTF-8').strip()
    for path in tree.splitlines():
        yield (repo_root() / Path(path)).absolute()


def main():
    parser = argparse.ArgumentParser(
        description="to update years, use the --fix option"
    )
    parser.add_argument("--file", type=Path)
    parser.add_argument(
        "--fix", action="store_true", help="modify files with correct year"
    )
    args = parser.parse_args()

    root = repo_root()
    ret = 0
    if args.file:
        sys.exit(check_file(root, args.file.resolve(), args.fix))
    for path in tracked_files():
        if path.suffix in EXTENSIONS:
            skip = False
            for path_start in SKIP_DIRS:
                if str(path).startswith(path_start):
                    skip = True
                    break
            if skip:
                continue

            ret |= check_file(root, path, args.fix)
    sys.exit(ret)


if __name__ == "__main__":
    main()
