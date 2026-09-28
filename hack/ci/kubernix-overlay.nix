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

# Nix overlay for the kubernix cluster which records the seccomp base profiles.
# It replaces the OCI runtimes of the pinned nixpkgs with the upstream release
# binaries of the versions in dependencies.yaml, because the recorded profiles
# are named and published after them. Update the hashes together with the
# versions. kubernix copies this file on its own, so it cannot import others.
final: prev:
let
  crunVersion = "1.30.1";
  runcVersion = "v1.5.2";

  arch =
    {
      x86_64-linux = "amd64";
      aarch64-linux = "arm64";
    }
    .${prev.stdenv.hostPlatform.system};

  release =
    name: version: url: hashes:
    prev.runCommand "${name}-${version}"
      {
        src = prev.fetchurl {
          inherit url;
          hash = hashes.${arch};
        };
        meta.mainProgram = name;
      }
      ''
        install -Dm755 $src $out/bin/${name}
      '';
in
{
  crun =
    release "crun" crunVersion
      "https://github.com/containers/crun/releases/download/${crunVersion}/crun-${crunVersion}-linux-${arch}"
      {
        amd64 = "sha256-htHmoOdpRZddOuv6s5y8aibuoV8cP8ZrZ3bRnl3DRqA=";
        arm64 = "sha256-DvMLD7tJTcnFMD1GsJGoTifLismcmFEj+x6zOYVLaeo=";
      };

  runc =
    release "runc" runcVersion
      "https://github.com/opencontainers/runc/releases/download/${runcVersion}/runc.${arch}"
      {
        amd64 = "sha256-WZ9vlP+MUFckHv8NVMPHT5XDSTW2RXsz/lRd78YelIg=";
        arm64 = "sha256-0Q7K6Jg2GDKgWb4gibq5LRWK7FRmGxjtc0bteWKLRrA=";
      };

  # podman does not run the cluster workloads, so it keeps the runtimes it was
  # built with. Otherwise it would be built from source instead of substituted.
  podman = prev.podman.override { inherit (prev) crun runc; };
}
