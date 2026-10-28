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

"""Checks the dependencies whose releases zeitgeist cannot find or parse.

zeitgeist only understands semantic version tags with an optional v prefix and
fails on dependencies with other tags. Its GitHub upstream only knows releases,
which some Go projects do not publish, and it knows no Go releases. The
dependencies below therefore have no upstream in dependencies.yaml, and this
script compares their versions there with the latest GitHub release whose tag
matches their pattern, the latest version of a Go module on the module proxy,
or the latest patch release of Go, instead. It prints the available updates
like zeitgeist and a "Check failed" line for each dependency whose releases it
cannot get, which make verify-dependencies-upstream fails on. Set GITHUB_TOKEN
for the API rate limit.
"""

import http.client
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

# The name in dependencies.yaml and the Go module whose latest version on the
# module proxy is the latest release. The GitHub mirrors of the golang.org/x
# repositories have tags, but no current releases.
MODULES = [
    ("govulncheck", "golang.org/x/vuln"),
]

# The name of Go in dependencies.yaml. Only patch releases of its minor
# version count, a new minor version needs more than a bump.
GOLANG = "golang"


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
        raise ValueError(f"no release of {repo} matches {pattern}")
    return max(found, key=parse)


def fetch_json(url):
    with urllib.request.urlopen(url, timeout=60) as response:
        return json.load(response)


def latest_module(proxy, module):
    """Returns the latest version of module on the Go module proxy."""
    return fetch_json(f"{proxy}/{module}/@latest")["Version"]


def latest_go_patch(current):
    """Returns the latest stable Go release of the minor version of current."""
    minor = current.split(".")[:2]
    found = [
        release["version"].removeprefix("go")
        for release in fetch_json("https://go.dev/dl/?mode=json&include=all")
        if release.get("stable")
    ]
    found = [version for version in found if version.split(".")[:2] == minor]
    if not found:
        raise ValueError(f"no stable Go release of {'.'.join(minor)}")
    return max(found, key=parse)


def report(name, current, latest):
    # The version keeps the v prefix style of dependencies.yaml.
    latest = latest.removeprefix("v")
    if current.startswith("v"):
        latest = f"v{latest}"
    if parse(latest) > parse(current):
        print(f"Update available for dependency {name}: {latest} (current: {current})")
    else:
        print(f"No update available for dependency {name}: {current} (latest: {latest})")


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "dependencies.yaml"
    api = os.environ.get("GITHUB_API_URL", "https://api.github.com")
    proxy = "https://proxy.golang.org"
    pinned = versions(path)
    checks = [
        (name, lambda repo=repo, pattern=pattern: latest_release(api, repo, pattern))
        for name, repo, pattern in DEPENDENCIES
    ]
    checks += [
        (name, lambda module=module: latest_module(proxy, module))
        for name, module in MODULES
    ]
    checks.append((GOLANG, lambda: latest_go_patch(pinned[GOLANG])))
    missing = [name for name, _ in checks if name not in pinned]
    if missing:
        sys.exit(f"{path} has no dependencies {', '.join(missing)}")

    for name, latest in checks:
        try:
            report(name, pinned[name], latest())
        # A connection which breaks while the response gets read raises an
        # HTTPException, which is no OSError. A response without the expected
        # fields raises a KeyError or a TypeError.
        except (OSError, ValueError, KeyError, TypeError, http.client.HTTPException) as error:
            print(f"Check failed for dependency {name}: {error}")


if __name__ == "__main__":
    main()
