#!/bin/sh
# Entrypoint of the demo's web service: nginx on port 80, then
# myownpki-agent as the main process. The agent enrolls (it waits in
# Agents -> Enrollment requests until an admin approves it), gets a
# certificate for web.demo.test by http-01 through the webroot, writes it below
# /etc/nginx/myownpki/web and reloads nginx. As soon as the certificate exists
# a small loop adds the TLS server block and reloads nginx once.
#
# No secret is involved: the root certificate comes from the demo volume
# /trust, and the host name and URLs are fixed demo values.
set -eu

host=web.demo.test
state=/var/lib/myownpki-agent
cert_dir=/etc/nginx/myownpki/web

echo "demo web: waiting for the demo root in /trust/root.pem (run ./demo.sh certbot first)"
n=0
while [ ! -s /trust/root.pem ]; do
  n=$((n + 1))
  [ "$n" -le 120 ] || { echo "demo web: /trust/root.pem did not appear" >&2; exit 1; }
  sleep 1
done
install -m 0644 /trust/root.pem /etc/myownpki-agent/root.pem
install -d -m 0700 "$state"

cat >/etc/myownpki-agent/agent.yaml <<EOF
server: "https://agent.demo.test:8444"
ca_bundle: "/etc/myownpki-agent/root.pem"
hostname: "$host"
state_dir: "$state"
log_level: "info"
acme_directory: "https://acme.demo.test:8443/acme/directory"
enrollment:
  challenge: webroot
  webroot: "/var/www/html"
hooks:
  nginx-test: ["/usr/sbin/nginx", "-t"]
  nginx-reload: ["/usr/sbin/nginx", "-s", "reload"]
paths: ["/var/www/html", "/etc/nginx/myownpki"]
deployments:
  - name: web
    profile: nginx
    names: ["$host"]
    challenge: webroot
    webroot: "/var/www/html"
    dir: "$cert_dir"
    test_hook: nginx-test
    reload_hook: nginx-reload
EOF

cat >/etc/nginx/conf.d/demo.conf <<EOF
server {
    listen 80 default_server;
    server_name $host;
    root /var/www/html;
    location /.well-known/acme-challenge/ {
        try_files \$uri =404;
    }
    location / {
        default_type text/plain;
        return 200 "MyOwnPKI demo: http\n";
    }
}
EOF

/usr/local/bin/myownpki-agent config check --config /etc/myownpki-agent/agent.yaml
nginx -t
nginx

# One reload when the agent has written the first certificate.
(
  while [ ! -s "$cert_dir/fullchain.pem" ] || [ ! -s "$cert_dir/privkey.pem" ]; do
    sleep 2
  done
  cat >/etc/nginx/conf.d/demo-tls.conf <<EOF
server {
    listen 443 ssl;
    server_name $host;
    ssl_certificate $cert_dir/fullchain.pem;
    ssl_certificate_key $cert_dir/privkey.pem;
    location / {
        default_type text/plain;
        return 200 "MyOwnPKI demo: https, certificate by myownpki-agent\n";
    }
}
EOF
  nginx -t && nginx -s reload
  echo "demo web: nginx serves $host on port 443 with the certificate of the agent"
) &

exec /usr/local/bin/myownpki-agent run --config /etc/myownpki-agent/agent.yaml
