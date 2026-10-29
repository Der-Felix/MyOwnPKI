# Container image of the MyOwnPKI server – built by GoReleaser (dockers_v2 in
# .goreleaser.yaml) from the release binaries; it does not compile anything.
# The build context holds linux/<arch>/myownpki for each platform, so a plain
# `docker build` in the repository does not work: use `task release:snapshot`
# on a machine with Docker, or the released image ghcr.io/der-felix/myownpki.
#
# Distroless static, non-root (UID 65532), pinned by digest (two-week rule):
# no shell, no package manager – only the static Go binary, CA certificates
# and /etc/passwd. Update the digest deliberately (THIRD_PARTY.md).
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

ARG TARGETPLATFORM

COPY ${TARGETPLATFORM}/myownpki /usr/local/bin/myownpki

# The exact release's immutable agent packages for both architectures. The
# nonroot server only reads this directory; no runtime download is needed.
COPY dist/checksums.txt /opt/myownpki/agent-dist/checksums.txt
COPY dist/myownpki-agent_*.deb /opt/myownpki/agent-dist/
COPY dist/myownpki-agent_*.rpm /opt/myownpki/agent-dist/
COPY dist/myownpki-agent_*.tar.gz /opt/myownpki/agent-dist/
# agent.package_dir for the container (docs/OPERATIONS.md §2.2); the host
# default /var/lib/myownpki/agent-dist is the data volume and holds none.
ENV MYOWNPKI_AGENT_PACKAGE_DIR=/opt/myownpki/agent-dist

# The data directory (data_dir), empty and owned by nonroot. There is no
# shell for mkdir/chown, so the base image's own empty, 0700 nonroot home
# is copied; a new named volume takes over this owner and mode.
COPY --from=gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab --chown=65532:65532 /home/nonroot /var/lib/myownpki
VOLUME ["/var/lib/myownpki"]

# The configuration is mounted read-only at /etc/myownpki/config.yaml (the
# default path); deploy/docker/config.yaml is a start. No secrets in it.

# 9443: admin listener (HTTPS, web UI and API). 8080: public listener (CRLs,
# CA certificates) – it must be reachable under the CA's base URL.
EXPOSE 9443 8080

USER 65532:65532

# `myownpki healthcheck` asks /healthz on loopback and pins the served
# certificate; keep 127.0.0.1 in admin.allowed_networks when you set it.
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD ["/usr/local/bin/myownpki", "healthcheck"]

ENTRYPOINT ["/usr/local/bin/myownpki"]
CMD ["serve"]
