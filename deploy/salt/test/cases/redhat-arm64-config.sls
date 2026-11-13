# RedHat, arm64 (grain osarch aarch64), no pass, agent.yaml rendered from config_source.
# Rendered only: the CI runner has no rpm, so pkg.installed cannot run there.
# grain: os_family=RedHat
# grain: osarch=aarch64
# present: myownpki-agent-pass-absent
# mode: render
# present: myownpki-agent-package-file
# present: myownpki-agent-package
# present: myownpki-agent-config
# present: myownpki-agent-setup
# present: myownpki-agent-sandbox
# present: myownpki-agent-restart
# present: myownpki-agent-system-trust
# absent: myownpki-agent-pass
# absent: myownpki-agent-deployment-proxy
# absent: myownpki-agent-refused
# contains: --package-format rpm
# contains: myownpki-agent_0.3.6_linux_arm64.rpm
# contains: sandbox sync
# contains: trust install --root-sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef --no-record
# not-contains: --token-file
# not-contains: --webroot
myownpki:
  agent:
    version: "0.3.6"
    server: https://pki.homelab.lan:8444
    acme_directory: https://pki.homelab.lan/acme/directory
    root_source: salt://test/files/root.pem
    root_sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    system_trust: true
    package:
      source: salt://test/files/{name}
      sha256:
        arm64: "5826cefc719f2d48e08923ec0ec5d1ca8d798039f8b29b2d73218ed8f36d7b17"
    config_source: salt://test/files/agent.yaml
