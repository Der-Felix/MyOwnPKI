#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
: "${RUNNER_TEMP:?set RUNNER_TEMP}"

fixtures=$RUNNER_TEMP/agent-package-fixtures
mkdir -p "$fixtures"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=MyOwnPKI-package-test \
  -keyout "$fixtures/key.pem" -out "$fixtures/root.pem" >/dev/null 2>&1
package=$(compgen -G 'dist/myownpki-agent_*_linux_amd64.deb')
archive=$(compgen -G 'dist/myownpki-agent_*_linux_amd64.tar.gz')
[ -f "$package" ] && [ -f "$archive" ]
# Unpack on the runner, not in the containers: minimal images such as
# rockylinux:9 have no cmp (diffutils); sha256sum (coreutils) is everywhere.
rm -rf "$fixtures/tarball"
mkdir "$fixtures/tarball"
tar -xzf "$archive" -C "$fixtures/tarball"

deb_test='
set -euo pipefail
package=$1
export DEBIAN_FRONTEND=noninteractive
dpkg -i "$package" >/dev/null
[ ! -e /etc/systemd/system/myownpki-agent.service ]
[ ! -e /etc/systemd/system/multi-user.target.wants/myownpki-agent.service ]
printf "# local administrator change\n" >>/etc/myownpki-agent/agent.yaml
dpkg -i "$package" >/dev/null
grep -Fqx "# local administrator change" /etc/myownpki-agent/agent.yaml
same() { [ "$(sha256sum <"$1")" = "$(sha256sum <"$2")" ] || { echo "$1 differs from the archive" >&2; exit 1; }; }
same /usr/local/bin/myownpki-agent /fixtures/tarball/myownpki-agent
same /usr/share/myownpki-agent/examples/agent.yaml /fixtures/tarball/deploy/agent.example.yaml
same /usr/share/myownpki-agent/examples/myownpki-agent.service /fixtures/tarball/deploy/systemd/myownpki-agent.service
same /usr/share/myownpki-agent/examples/agent-low-ports.conf /fixtures/tarball/deploy/systemd/agent-low-ports.conf
if /usr/local/bin/myownpki-agent setup --server https://pki.homelab.lan:8444 --ca-bundle /fixtures/root.pem --root-sha256 0000000000000000000000000000000000000000000000000000000000000000; then
  echo wrong root fingerprint accepted >&2
  exit 1
fi
[ ! -e /etc/systemd/system/myownpki-agent.service ]
'
rpm_test='
set -euo pipefail
package=$1
rpm -Uvh "$package" >/dev/null
[ ! -e /etc/systemd/system/myownpki-agent.service ]
[ ! -e /etc/systemd/system/multi-user.target.wants/myownpki-agent.service ]
printf "# local administrator change\n" >>/etc/myownpki-agent/agent.yaml
rpm -Uvh --replacepkgs "$package" >/dev/null
grep -Fqx "# local administrator change" /etc/myownpki-agent/agent.yaml
same() { [ "$(sha256sum <"$1")" = "$(sha256sum <"$2")" ] || { echo "$1 differs from the archive" >&2; exit 1; }; }
same /usr/local/bin/myownpki-agent /fixtures/tarball/myownpki-agent
same /usr/share/myownpki-agent/examples/agent.yaml /fixtures/tarball/deploy/agent.example.yaml
same /usr/share/myownpki-agent/examples/myownpki-agent.service /fixtures/tarball/deploy/systemd/myownpki-agent.service
same /usr/share/myownpki-agent/examples/agent-low-ports.conf /fixtures/tarball/deploy/systemd/agent-low-ports.conf
if /usr/local/bin/myownpki-agent setup --server https://pki.homelab.lan:8444 --ca-bundle /fixtures/root.pem --root-sha256 0000000000000000000000000000000000000000000000000000000000000000; then
  echo wrong root fingerprint accepted >&2
  exit 1
fi
[ ! -e /etc/systemd/system/myownpki-agent.service ]
'

images=(
  'debian:12@sha256:854dd8ab51d62866dbd8f5431d15ce77b12983a2a4a1e1fe43a2395dc7ef9f61|deb'
  'debian:13@sha256:4c25275446ca371766b8b093c696782eabce06263fccacb8d5d813b3dc44b308|deb'
  'ubuntu:24.04@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac|deb'
  'rockylinux:9@sha256:d7be1c094cc5845ee815d4632fe377514ee6ebcf8efaed6892889657e5ddaaa6|rpm'
  'rockylinux/rockylinux:10@sha256:827d37bc128288ccf160ee318bb3cb92d591164cb217e92f8bc61e3982ae1834|rpm'
  'almalinux:9@sha256:9819dc675b67b595c2b59e42be7763fca1a8bb217fa5944e04daa22e9a64db16|rpm'
  'almalinux:10@sha256:838c2fafefb1a8a0d7f8cdbc3b0551c2a2b1eb0cd87aad6d62aecadb18311f1b|rpm'
)
for entry in "${images[@]}"; do
  image=${entry%|*}
  family=${entry##*|}
  package=$(compgen -G "dist/myownpki-agent_*_linux_amd64.$family")
  printf 'Testing %s in %s\n' "$(basename "$package")" "$image"
  script=$deb_test
  [ "$family" = deb ] || script=$rpm_test
  docker run --rm --volume "$PWD/dist:/work:ro" --volume "$fixtures:/fixtures:ro" \
    "$image" bash -c "$script" bash "/work/$(basename "$package")"
done
