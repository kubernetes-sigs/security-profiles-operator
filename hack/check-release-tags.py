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

"""Checks the dependencies with release tags zeitgeist cannot parse.

zeitgeist only understands semantic version tags with an optional v prefix and
fails its whole upstream check on the first dependency with other tags. The
dependencies below therefore have no upstream in dependencies.yaml, and this
script compares their versions there with the latest GitHub release whose tag
matches their pattern instead. It prints the available updates like zeitgeist,
which make verify-dependencies-upstream fails on. Set GITHUB_TOKEN for the API
rate limit.
"""

import json
import os
import re
import sys
import urllib.request

# The name in dependencies.yaml, the GitHub repository and the pattern of its
# release tags, whose group is the version.
DEPENDENCIES = [
    # kustomize 6 would be a major update with breaking changes.
    ("kustomize", "kubernetes-sigs/kustomize", r"kustomize/v(5\.\d+\.\d+)"),
    ("jq", "jqlang/jq", r"jq-(\d+\.\d+(?:\.\d+)?)"),
    ("protoc", "protocolbuffers/protobuf", r"v(\d+\.\d+(?:\.\d+)?)"),
    # The repository releases the lychee-lib crate too.
    ("lychee", "lycheeverse/lychee", r"lychee-v(\d+\.\d+\.\d+)"),
]


def versions(path):
    """Returns the versions of dependencies.yaml by name."""
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    return dict(re.findall(r"^  - name: (\S+)\n    version: (\S+)$", text, re.MULTILINE))


def parse(version):
    return tuple(int(part) for part in version.removeprefix("v").split("."))


def latest_release(api, repo, pattern):
    """Returns the highest version of the latest 100 releases of repo."""
    request = urllib.request.Request(f"{api}/repos/{repo}/releases?per_page=100")
    request.add_header("Accept", "application/vnd.github+json")
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=60) as response:
        releases = json.load(response)

    found = [
        match.group(1)
        for release in releases
        if not release.get("draft") and not release.get("prerelease")
        for match in [re.fullmatch(pattern, release.get("tag_name", ""))]
        if match
    ]
    if not found:
        sys.exit(f"no release of {repo} matches {pattern}")
    return max(found, key=parse)


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "dependencies.yaml"
    api = os.environ.get("GITHUB_API_URL", "https://api.github.com")
    pinned = versions(path)
    missing = [name for name, _, _ in DEPENDENCIES if name not in pinned]
    if missing:
        sys.exit(f"{path} has no dependencies {', '.join(missing)}")

    for name, repo, pattern in DEPENDENCIES:
        current = pinned[name]
        latest = latest_release(api, repo, pattern)
        # The version keeps the v prefix style of dependencies.yaml.
        if current.startswith("v"):
            latest = f"v{latest}"
        if parse(latest) > parse(current):
            print(f"Update available for dependency {name}: {latest} (current: {current})")
        else:
            print(f"No update available for dependency {name}: {current} (latest: {latest})")


if __name__ == "__main__":
    main()
