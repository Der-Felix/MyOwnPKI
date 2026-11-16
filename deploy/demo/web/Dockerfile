# The web service of the demo's second act: nginx served by myownpki-agent.
# A demo build, never an image to run in production (docs/PHASE3.md §17.6).
#
# The agent is not downloaded: it is the agent tarball of the exact release,
# taken from the server image (/opt/myownpki/agent-dist) and checked against
# the checksums.txt that comes with it. The server image is the variable
# MYOWNPKI_IMAGE of the compose file (a snapshot in CI, the release tag
# otherwise).
ARG MYOWNPKI_IMAGE=ghcr.io/der-felix/myownpki:0.9.0
FROM ${MYOWNPKI_IMAGE} AS server

# nginx 1.31.7 on Debian 13, index uploaded 2026-10-21 (two-week rule), BSD-2-Clause.
FROM nginx:1.31.7-trixie@sha256:8632b3314d74c61f0e27f59055bab13f7793b988c94c090154d867bc29e0f39b

ARG TARGETARCH

COPY --from=server /opt/myownpki/agent-dist /tmp/agent-dist
RUN set -eu; \
    cd /tmp/agent-dist; \
    set -- myownpki-agent_*_linux_"${TARGETARCH}".tar.gz; \
    [ "$#" -eq 1 ] && [ -f "$1" ] || { echo "want exactly one agent tarball for ${TARGETARCH}, found: $*" >&2; exit 1; }; \
    grep -F "  $1" checksums.txt | sha256sum -c -; \
    mkdir /tmp/agent; \
    tar -xzf "$1" -C /tmp/agent; \
    install -m 0755 "$(find /tmp/agent -name myownpki-agent -type f | head -n 1)" /usr/local/bin/myownpki-agent; \
    /usr/local/bin/myownpki-agent --version; \
    rm -rf /tmp/agent /tmp/agent-dist

COPY --chmod=0755 entrypoint.sh /usr/local/bin/demo-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/demo-entrypoint.sh"]
