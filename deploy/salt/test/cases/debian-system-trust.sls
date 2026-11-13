# The root in the system trust store: one extra state after setup, no change to the service states.
# The pin goes to the command and to its guard; the guard makes the second apply a no-op.
# grain: os_family=Debian
# grain: osarch=amd64
# present: myownpki-agent-setup
# present: myownpki-agent-system-trust
# absent: myownpki-agent-config
# absent: myownpki-agent-sandbox
# absent: myownpki-agent-restart
# absent: myownpki-agent-refused
# contains: myownpki-agent trust install --root-sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
# contains: myownpki-agent trust status --quiet --root-sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
# not-contains: --no-record
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
        amd64: "5d94d19886d62aaa0163dcf72ed852b46948cd7e6a72c56b90aa4b6eb1f00ce4"
