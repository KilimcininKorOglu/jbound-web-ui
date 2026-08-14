# Development image for the unbound-web panel.
#
# The panel runs unprivileged. Only the setuid helper touches PAM. No Unbound
# runs here, because the panel manages remote targets over SSH.

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
        rsyslog \
        openssh-client \
        sudo \
        gcc \
        make \
        cppcheck \
        procps \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Service account. The panel process and the air supervisor both run as this
# user. The helper is executable only by this group.
RUN groupadd --system unbound-web \
    && useradd --system --gid unbound-web --create-home \
        --home-dir /home/unbound-web --shell /usr/sbin/nologin unbound-web

COPY deploy/pam.d-unbound-web /etc/pam.d/unbound-web
COPY docker/rsyslog-app.conf /etc/rsyslog.conf
RUN mkdir -p /var/spool/rsyslog /etc/rsyslog.d /usr/local/libexec

# The container has no systemd. These two helpers stand in for the systemctl
# commands the panel runs in production.
COPY docker/rsyslog-restart /usr/local/bin/rsyslog-restart
RUN chmod 0755 /usr/local/bin/rsyslog-restart

# Mirrors the production sudoers rules for the panel account.
RUN printf '%s\n' \
        'unbound-web ALL=(ALL) NOPASSWD: /usr/local/bin/rsyslog-restart' \
        'unbound-web ALL=(ALL) NOPASSWD: /usr/sbin/rsyslogd -N1' \
        > /etc/sudoers.d/unbound-web \
    && chmod 0440 /etc/sudoers.d/unbound-web \
    && visudo -c -f /etc/sudoers.d/unbound-web

# Hot reload for the Go binary. Installed as root, used by the service account.
#
# Pinned like every analyser in the Makefile. This is the process the panel
# runs under, in a container that bind mounts the host source tree read write,
# holds the development SSH key and carries two NOPASSWD sudoers rules, so an
# unpinned reference would let whatever the proxy serves that day reach all
# three.
RUN go install github.com/air-verse/air@v1.67.4 \
    && install -m 0755 /go/bin/air /usr/local/bin/air

# Shared Go caches so the unprivileged account can build.
ENV GOPATH=/go \
    GOCACHE=/go/cache \
    GOMODCACHE=/go/pkg/mod
RUN mkdir -p /go/cache /go/pkg/mod \
    && chown -R unbound-web:unbound-web /go

COPY docker/testusers.sh /usr/local/bin/testusers.sh
COPY docker/entrypoint-app.sh /usr/local/bin/entrypoint-app.sh
RUN chmod 0755 /usr/local/bin/testusers.sh /usr/local/bin/entrypoint-app.sh

WORKDIR /src

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/entrypoint-app.sh"]
