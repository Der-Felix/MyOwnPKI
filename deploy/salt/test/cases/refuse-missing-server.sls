# A required key (server) is missing.
# grain: os_family=Debian
# grain: osarch=amd64
# refused: missing required pillar key myownpki:agent:server
myownpki:
  agent:
    version: "0.3.6"
    acme_directory: https://pki.homelab.lan/acme/directory
    root_source: salt://test/files/root.pem
    root_sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    package:
      sha256:
        amd64: "5d94d19886d62aaa0163dcf72ed852b46948cd7e6a72c56b90aa4b6eb1f00ce4"
