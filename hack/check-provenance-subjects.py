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

"""Checks that every published spoc architecture has a provenance subject.

Adding an architecture to the nix-spoc-push matrix without adding it to the
provenance SUBJECTS in the spoc-sbom job would publish a release artifact
with no provenance, and nothing in the release jobs catches that. Running this
on every pull request means the change that adds the architecture fails
instead.
"""

import re
import sys

WORKFLOW = ".github/workflows/build.yml"

# The SBOM is a subject too, but it is not per-architecture.
NON_ARCH_SUBJECTS = {"spoc.spdx.json"}


def block(text, header, pattern):
    """Returns the pattern matches in the indented block following header.

    An empty result means the header moved or was reformatted, which the caller
    reports rather than letting it surface as a traceback.
    """
    start = text.find(header)
    if start < 0:
        return []

    start += len(header)
    lines = []
    for line in text[start:].split("\n"):
        if line.strip() and not line.startswith(" "):
            break
        match = pattern.fullmatch(line.strip())
        if match:
            lines.append(match.group(1))
        elif lines:
            break
    return lines


def main():
    with open(WORKFLOW, encoding="utf-8") as handle:
        text = handle.read()

    arches = block(
        text,
        "  nix-spoc-push:\n    strategy:\n      fail-fast: false\n      matrix:\n        arch:\n",
        re.compile(r"- (\S+)"),
    )
    subjects = block(text, "          SUBJECTS: |\n", re.compile(r"(spoc\.\S+)"))

    if not arches:
        sys.exit(f"could not read the nix-spoc-push architectures from {WORKFLOW}")
    if not subjects:
        sys.exit(f"could not read the provenance subjects from {WORKFLOW}")

    want = {f"spoc.{arch}" for arch in arches}
    got = set(subjects) - NON_ARCH_SUBJECTS

    failed = False
    for subject in sorted(want - got):
        print(f"::error::{subject} is built and published but has no provenance subject")
        failed = True
    for subject in sorted(got - want):
        print(f"::error::{subject} is a provenance subject with no matching architecture")
        failed = True

    if failed:
        sys.exit(1)

    print(f"all {len(want)} published architectures have a provenance subject")


if __name__ == "__main__":
    main()
