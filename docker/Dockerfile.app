# Development image for the JBound panel.
#
# The panel runs unprivileged and holds no root command. Only the setuid helper
# touches PAM. No Unbound runs here, because the panel manages remote targets
# over SSH.

# Pinned to the patch level, not to 1.26. A floating tag would ship whatever
# the base image happens to resolve to, which is the same hole the toolchain
# line in go.mod closes for the build itself.
FROM golang:1.26.6-bookworm

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install --no-install-recommends -y \
        libpam0g-dev \
        libpam-modules \
        libpam-runtime \
        passwd \
        dnsutils \
        openssh-client \
        gcc \
        make \
        cppcheck \
        procps \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Service account. The panel process and the air supervisor both run as this
# user. The helper is executable only by this group.
RUN groupadd --system jbound \
    && useradd --system --gid jbound --create-home \
        --home-dir /home/jbound --shell /usr/sbin/nologin jbound

COPY deploy/pam.d-jbound /etc/pam.d/jbound
RUN mkdir -p /usr/local/libexec

# No sudo and no sudoers file. The panel account holds no root command at all:
# PAM goes through the setuid helper, and the audit trail goes to the sink over
# a socket. A development stack that carried a rule production does not would
# hide the boundary rather than prove it.

# Hot reload for the Go binary. Installed as root, used by the service account.
#
# Pinned like every analyser in the Makefile. This is the process the panel
# runs under, in a container that bind mounts the host source tree read write
# and holds the development SSH key, so an unpinned reference would let
# whatever the proxy serves that day reach both.
RUN go install github.com/air-verse/air@v1.67.4 \
    && install -m 0755 /go/bin/air /usr/local/bin/air

# Shared Go caches so the unprivileged account can build.
ENV GOPATH=/go \
    GOCACHE=/go/cache \
    GOMODCACHE=/go/pkg/mod
RUN mkdir -p /go/cache /go/pkg/mod \
    && chown -R jbound:jbound /go

COPY docker/testusers.sh /usr/local/bin/testusers.sh
COPY docker/entrypoint-app.sh /usr/local/bin/entrypoint-app.sh
RUN chmod 0755 /usr/local/bin/testusers.sh /usr/local/bin/entrypoint-app.sh

WORKDIR /src

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/entrypoint-app.sh"]
