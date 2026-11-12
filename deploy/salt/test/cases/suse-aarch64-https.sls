# Suse derives rpm. An https package source is allowed because Salt checks source_hash for it.
# Rendered only: an apply would download from the network.
# grain: os_family=Suse
# grain: osarch=aarch64
# mode: render
# present: myownpki-agent-package-file
# present: myownpki-agent-package-verified
# absent: myownpki-agent-refused
# contains: --package-format rpm
# contains: sha256=5826cefc719f2d48e08923ec0ec5d1ca8d798039f8b29b2d73218ed8f36d7b17
# contains: https://pki.homelab.lan/files/myownpki-agent_0.3.6_linux_arm64.rpm
myownpki:
  agent:
    version: "0.3.6"
    server: https://pki.homelab.lan:8444
    acme_directory: https://pki.homelab.lan/acme/directory
    root_source: salt://test/files/root.pem
    root_sha256: 01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF
    package:
      source: https://pki.homelab.lan/files/{name}
      sha256:
        arm64: "5826cefc719f2d48e08923ec0ec5d1ca8d798039f8b29b2d73218ed8f36d7b17"
