# A dns option next to another challenge is a mistake that would be ignored at run time.
# grain: os_family=Debian
# grain: osarch=amd64
# refused: deployment "proxy": the options dns_provider, dns_type only go with challenge: dns-01
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
      proxy:
        recipe: nginx
        challenge: webroot
        webroot: /var/www/html
        dns_provider: homelab-dns
        dns_type: rfc2136
