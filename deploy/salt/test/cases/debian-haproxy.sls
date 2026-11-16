# The haproxy recipe through the formula: one deployment with two names. The recipe sets "combined" itself
# (one PEM file with the chain and the key); the formula passes no --combined, which is the option for a path of your own.
# Render only: the package fixtures stop at 0.3.9, and nothing here depends on the file.
# grain: os_family=Debian
# grain: osarch=amd64
# mode: render
# present: myownpki-agent-package
# present: myownpki-agent-root
# present: myownpki-agent-setup
# present: myownpki-agent-deployment-haproxy
# present: myownpki-agent-restart
# absent: myownpki-agent-pass
# absent: myownpki-agent-config
# absent: myownpki-agent-sandbox
# absent: myownpki-agent-refused
# contains: deployment add haproxy --recipe haproxy --challenge webroot --webroot /var/www/acme --name lb-01.homelab.lan --name lb.homelab.lan --create-dirs
# not-contains: --combined
# not-contains: --low-ports
myownpki:
  agent:
    version: "0.3.11"
    server: https://pki.homelab.lan:8444
    acme_directory: https://pki.homelab.lan/acme/directory
    root_source: salt://test/files/root.pem
    root_sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    package:
      source: salt://test/files/{name}
      sha256:
        amd64: "5d94d19886d62aaa0163dcf72ed852b46948cd7e6a72c56b90aa4b6eb1f00ce4"
    deployments:
      haproxy:
        recipe: haproxy
        challenge: webroot
        webroot: /var/www/acme
        name: [lb-01.homelab.lan, lb.homelab.lan]
        create_dirs: true
