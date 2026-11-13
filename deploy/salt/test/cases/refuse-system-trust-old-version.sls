# "trust install" exists in agent 0.3.9 and later: an older version is refused before the old package is installed.
# grain: os_family=Debian
# grain: osarch=amd64
# refused: myownpki:agent:system_trust needs agent 0.3.9 or later (the command "trust install" does not exist before), the pillar version is "0.3.8"
myownpki:
  agent:
    version: "0.3.8"
    server: https://pki.homelab.lan:8444
    acme_directory: https://pki.homelab.lan/acme/directory
    root_source: salt://test/files/root.pem
    root_sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    system_trust: true
    package:
      source: salt://test/files/{name}
      sha256:
        amd64: "5d94d19886d62aaa0163dcf72ed852b46948cd7e6a72c56b90aa4b6eb1f00ce4"
