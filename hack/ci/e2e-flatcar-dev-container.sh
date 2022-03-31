#!/usr/bin/env bash

set -ue

dev() {
  systemd-nspawn -q -i /opt/bin/flatcar_developer_container.bin --bind=/:/hostfs ${@}
}

dev --chdir=/hostfs/vagrant -- /hostfs/vagrant/hack/ci/e2e-flatcar.sh
