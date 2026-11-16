#!/bin/sh
# Runs inside the certbot container (./demo.sh certbot): fetch the demo root
# from the public listener, wait until the ACME server speaks TLS with a
# certificate of that root, then get a certificate for www.demo.test by http-01.
#
# The root arrives over plain HTTP, like on any new client: the fingerprint is
# printed and ./demo.sh compares it with the one the authenticated admin API
# reports. Nothing here is a secret.
set -eu

root_url=http://myownpki:8080/ca/root/1.crt
acme_directory=https://acme.demo.test:8443/acme/directory
cert_name=demo
domain=www.demo.test

echo "== fetch the demo root and wait for the ACME server"
python3 - "$root_url" "$acme_directory" <<'PY'
import hashlib
import ssl
import sys
import time
import urllib.request

root_url, directory = sys.argv[1], sys.argv[2]

der = None
for _ in range(30):
    try:
        der = urllib.request.urlopen(root_url, timeout=5).read()
        break
    except Exception as err:
        last = err
        time.sleep(2)
if der is None:
    sys.exit("cannot read the root from %s: %s" % (root_url, last))

pem = ssl.DER_cert_to_PEM_cert(der)
with open("/trust/root.pem", "w") as f:
    f.write(pem)
print("root SHA-256: " + hashlib.sha256(der).hexdigest())

# The ACME listener serves a bootstrap certificate while the server is sealed
# and its own, issued by the demo CA, after the unseal.
ctx = ssl.create_default_context(cafile="/trust/root.pem")
for _ in range(60):
    try:
        urllib.request.urlopen(directory, context=ctx, timeout=5).read()
        print("ACME directory reachable over TLS with the demo root as trust anchor")
        break
    except Exception as err:
        last = err
        time.sleep(2)
else:
    sys.exit("the ACME server does not answer with a certificate of the demo root: %s" % last)
PY

echo "== certbot certonly --standalone for $domain"
# certbot trusts only the demo root for the ACME server (REQUESTS_CA_BUNDLE).
export REQUESTS_CA_BUNDLE=/trust/root.pem
if ! certbot certonly --standalone --non-interactive --agree-tos \
  --register-unsafely-without-email \
  --server "$acme_directory" \
  --cert-name "$cert_name" -d "$domain" \
  --preferred-challenges http --http-01-port 80; then
  echo "certbot failed; its log:" >&2
  tail -n 40 /var/log/letsencrypt/letsencrypt.log >&2 || true
  exit 1
fi

echo "== certificate files"
ls -l "/etc/letsencrypt/live/$cert_name/"
