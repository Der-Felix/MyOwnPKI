#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

rpm_image=rockylinux:9@sha256:d7be1c094cc5845ee815d4632fe377514ee6ebcf8efaed6892889657e5ddaaa6
required=(/etc/myownpki-agent/agent.yaml /usr/local/bin/myownpki-agent /usr/share/myownpki-agent/examples/agent.yaml /usr/share/myownpki-agent/examples/myownpki-agent.service /usr/share/myownpki-agent/examples/agent-low-ports.conf)
for arch in amd64 arm64; do
  for format in deb rpm; do
    package=$(compgen -G "dist/myownpki-agent_*_linux_${arch}.${format}")
    # shellcheck disable=SC2086
    set -- $package
    [ "$#" -eq 1 ] && [ -f "$1" ] || { echo "expected one $format for $arch" >&2; exit 1; }
    package=$1
    grep -F "  $(basename "$package")" checksums.txt >/dev/null 2>&1 || grep -F " $(basename "$package")" dist/checksums.txt >/dev/null
    if [ "$format" = deb ]; then
      dpkg-deb -f "$package" Package Version Architecture
      listing=$(dpkg-deb -c "$package")
      for path in "${required[@]}"; do
        grep -F " .${path}" <<<"$listing" >/dev/null || { echo "$package lacks $path" >&2; exit 1; }
      done
      dpkg-deb -I "$package" conffiles | grep -Fqx '/etc/myownpki-agent/agent.yaml'
      controls=$(dpkg-deb --ctrl-tarfile "$package" | tar -tf -)
      if grep -Ex './?(preinst|postinst|prerm|postrm)' <<<"$controls"; then
        echo "$package has a maintainer script" >&2
        exit 1
      fi
    else
      docker run --rm --volume "$PWD/dist:/work:ro" "$rpm_image" bash -c '
        set -euo pipefail
        package=$1
        rpm -qp --queryformat "%{NAME} %{VERSION}-%{RELEASE} %{ARCH}\n" "$package"
        listing=$(rpm -qlp "$package")
        for path in /etc/myownpki-agent/agent.yaml /usr/local/bin/myownpki-agent /usr/share/myownpki-agent/examples/agent.yaml /usr/share/myownpki-agent/examples/myownpki-agent.service /usr/share/myownpki-agent/examples/agent-low-ports.conf; do
          grep -Fqx "$path" <<<"$listing"
        done
        scripts=$(rpm -qp --scripts "$package")
        [ -z "$scripts" ] || { printf "%s\n" "$scripts" >&2; exit 1; }
      ' bash "/work/$(basename "$package")"
    fi
  done
done
printf 'Inspected agent deb/rpm packages for linux amd64/arm64: contents, conffile, no maintainer scripts.\n'
