# Debian, amd64, with an enrollment pass, two deployments and one removal.
# grain: os_family=Debian
# grain: osarch=amd64
# present: myownpki-agent-pass-absent
# mode: apply
# present: myownpki-agent-cache
# present: myownpki-agent-package-file
# present: myownpki-agent-package-verified
# present: myownpki-agent-package
# present: myownpki-agent-root
# present: myownpki-agent-pass
# present: myownpki-agent-setup-update
# present: myownpki-agent-setup
# present: myownpki-agent-deployment-proxy
# present: myownpki-agent-deployment-mail
# present: myownpki-agent-deployment-absent-old
# present: myownpki-agent-restart
# absent: myownpki-agent-config
# absent: myownpki-agent-sandbox
# absent: myownpki-agent-refused
# contains: --package-format deb
# contains: --token-file /root/myownpki-join-token
# contains: --webroot /var/www/html
# contains: --low-ports
# contains: deployment add proxy --recipe nginx
# contains: deployment remove old
# contains: contents_pillar
# contains: myownpki-agent_0.3.6_linux_amd64.deb
# not-contains: mjp_TESTSECRETTESTSECRETTESTSECRETTESTSECRET1
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
        arm64: "5826cefc719f2d48e08923ec0ec5d1ca8d798039f8b29b2d73218ed8f36d7b17"
    webroot: /var/www/html
    low_ports: true
    enrollment_pass: "mjp_TESTSECRETTESTSECRETTESTSECRETTESTSECRET1"
    deployments:
      proxy:
        recipe: nginx
        name: [minion-01.homelab.lan, www.homelab.lan]
        webroot: /var/www/html
        create_dirs: true
      mail:
        recipe: postfix
        key_mode: "0640"
        hook: ["postfix-test=/usr/sbin/postfix check"]
    absent:
      - old
