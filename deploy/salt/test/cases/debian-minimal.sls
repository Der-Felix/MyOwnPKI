# Only the required keys; osarch x86_64 is accepted as amd64. Nothing optional is rendered.
# grain: os_family=Debian
# grain: osarch=x86_64
# mode: apply
# present: myownpki-agent-package
# present: myownpki-agent-root
# present: myownpki-agent-setup
# absent: myownpki-agent-pass
# absent: myownpki-agent-config
# absent: myownpki-agent-sandbox
# absent: myownpki-agent-restart
# absent: myownpki-agent-refused
# not-contains: --token-file
# not-contains: --webroot
# not-contains: --low-ports
myownpki:
  agent:
    version: "0.3.6"
    server: https://pki.homelab.lan:8444
    acme_directory: https://pki.homelab.lan/acme/directory
    root_source: salt://test/files/root.pem
    root_sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    package:
      source: salt://test/files/{name}
      sha256:
        amd64: "5d94d19886d62aaa0163dcf72ed852b46948cd7e6a72c56b90aa4b6eb1f00ce4"
