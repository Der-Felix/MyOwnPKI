# The apache2 recipe through the formula: one deployment, webroot challenge, restart on change.
# The recipe is the agent's (0.3.11 and later, deployment add --recipe apache2); the formula only passes the name on.
# Render only: the package fixtures stop at 0.3.9, and nothing here depends on the file.
# grain: os_family=Debian
# grain: osarch=amd64
# mode: render
# present: myownpki-agent-package
# present: myownpki-agent-root
# present: myownpki-agent-setup
# present: myownpki-agent-deployment-apache2
# present: myownpki-agent-restart
# absent: myownpki-agent-pass
# absent: myownpki-agent-config
# absent: myownpki-agent-sandbox
# absent: myownpki-agent-refused
# contains: deployment add apache2 --recipe apache2 --challenge webroot --webroot /var/www/acme --name minion-01.homelab.lan --restart
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
      apache2:
        recipe: apache2
        challenge: webroot
        webroot: /var/www/acme
        name: minion-01.homelab.lan
        restart: true
