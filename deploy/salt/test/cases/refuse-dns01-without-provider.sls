# challenge dns-01 names no provider: the agent would refuse it at the first deployment add.
# grain: os_family=Debian
# grain: osarch=amd64
# refused: deployment "wild": challenge dns-01 needs the option dns_provider
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
    deployments:
      wild:
        recipe: nginx
        name: "*.homelab.lan"
        challenge: dns-01
