# The pass is a number (unquoted in the pillar); its value must not appear in the message.
# grain: os_family=Debian
# grain: osarch=amd64
# refused: myownpki:agent:enrollment_pass must be a string
# not-contains: 1234567890
myownpki:
  agent:
    version: "0.3.6"
    server: https://pki.homelab.lan:8444
    acme_directory: https://pki.homelab.lan/acme/directory
    root_source: salt://test/files/root.pem
    root_sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    package:
      sha256:
        amd64: "5d94d19886d62aaa0163dcf72ed852b46948cd7e6a72c56b90aa4b6eb1f00ce4"
    enrollment_pass: 1234567890
