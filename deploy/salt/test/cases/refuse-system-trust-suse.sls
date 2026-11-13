# The agent knows the trust stores of the Debian and RedHat families only.
# grain: os_family=Suse
# grain: osarch=aarch64
# refused: system_trust: the agent supports the system trust store of Debian and RedHat family hosts only, this minion has os_family "Suse"
myownpki:
  agent:
    version: "0.3.9"
    server: https://pki.homelab.lan:8444
    acme_directory: https://pki.homelab.lan/acme/directory
    root_source: salt://test/files/root.pem
    root_sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    system_trust: true
    package:
      source: salt://test/files/{name}
      sha256:
        arm64: "5826cefc719f2d48e08923ec0ec5d1ca8d798039f8b29b2d73218ed8f36d7b17"
