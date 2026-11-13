# A wildcard and a second deployment through dns-01, one DNS provider shared by both.
# The credentials file is a secret and is not part of the formula: the host's own state places it.
# grain: os_family=Debian
# grain: osarch=amd64
# present: myownpki-agent-pass-absent
# mode: apply
# present: myownpki-agent-package
# present: myownpki-agent-root
# present: myownpki-agent-setup
# present: myownpki-agent-deployment-wild
# present: myownpki-agent-deployment-api
# present: myownpki-agent-restart
# absent: myownpki-agent-pass
# absent: myownpki-agent-config
# absent: myownpki-agent-sandbox
# absent: myownpki-agent-refused
# contains: deployment add wild --recipe nginx --challenge dns-01 --check-name www.homelab.lan
# contains: --dns-provider homelab-dns --dns-type rfc2136 --dns-credentials /etc/myownpki-agent/dns/homelab.yaml --dns-nameserver 192.0.2.53 --dns-zone homelab.lan --dns-resolver 192.0.2.53
# contains: --name '*.homelab.lan' --name homelab.lan --create-dirs
# contains: deployment add api --recipe nginx --challenge dns-01 --dns-provider homelab-dns --name api.homelab.lan
# not-contains: --webroot
# not-contains: --low-ports
# not-contains: tsig_secret
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
        name: ["*.homelab.lan", homelab.lan]
        challenge: dns-01
        check_name: www.homelab.lan
        dns_provider: homelab-dns
        dns_type: rfc2136
        dns_credentials: /etc/myownpki-agent/dns/homelab.yaml
        dns_nameserver: 192.0.2.53
        dns_zone: homelab.lan
        dns_resolver: 192.0.2.53
        create_dirs: true
      api:
        recipe: nginx
        name: api.homelab.lan
        challenge: dns-01
        dns_provider: homelab-dns
        create_dirs: true
