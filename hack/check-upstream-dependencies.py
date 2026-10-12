#!/usr/bin/env python3
# Copyright The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Checks the dependencies with an upstream for updates, one at a time.

zeitgeist stops its whole upstream check on the first upstream it cannot
reach, which hides the updates of all other dependencies. This script runs it
for every dependency of dependencies.yaml with an upstream on its own, prints
the available updates like zeitgeist and a "Check failed" line for each
dependency zeitgeist fails on, which make verify-dependencies-upstream fails
on. Set GITHUB_TOKEN for the API rate limit.
"""

import os
import re
import subprocess
import sys
import tempfile


# ZEITGEIST_TIMEOUT bounds a single check, a stalled connection would
# otherwise run into the timeout of the job and hide all results.
ZEITGEIST_TIMEOUT = 300


def dependencies(path):
    """Returns the entries of dependencies.yaml with an upstream by name.

    The entries are split by their layout, so that each one can be checked on
    its own. A layout the split does not understand would skip entries, so the
    number of upstreams found has to match the number in the file.
    """
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    entries = re.split(r"^(?=  - name: )", text, flags=re.MULTILINE)[1:]
    found = {
        re.match(r"  - name: (\S+)", entry).group(1): entry
        for entry in entries
        if re.search(r"^    upstream:\s*(#.*)?$", entry, re.MULTILINE)
    }
    upstreams = len(re.findall(r"^\s*upstream:", text, re.MULTILINE))
    if not found or len(found) != upstreams:
        sys.exit(
            f"{path}: found {len(found)} dependencies with an upstream, but "
            f"{upstreams} upstream keys, the layout of the file changed"
        )
    return found


def main():
    zeitgeist = sys.argv[1]
    path = sys.argv[2] if len(sys.argv) > 2 else "dependencies.yaml"
    base = os.path.dirname(os.path.abspath(path))

    with tempfile.TemporaryDirectory() as tmp:
        config = os.path.join(tmp, "dependencies.yaml")
        for name, entry in dependencies(path).items():
            with open(config, "w", encoding="utf-8") as handle:
                handle.write("dependencies:\n" + entry)
            try:
                result = subprocess.run(
                    [zeitgeist, "validate", "--base-path", base, "--config", config],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=ZEITGEIST_TIMEOUT,
                )
            except subprocess.TimeoutExpired:
                print(f"Check failed for dependency {name}: timed out after {ZEITGEIST_TIMEOUT}s")
                continue
            sys.stdout.write(result.stdout)
            if result.returncode != 0:
                lines = result.stderr.strip().splitlines() or ["no output"]
                print(f"Check failed for dependency {name}: {lines[-1]}")


if __name__ == "__main__":
    main()
