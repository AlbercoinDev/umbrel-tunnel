FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf

# wg-quick is a bash script, so bash is required (Alpine's /bin/sh is ash).
# kmod + the /lib/modules mount let the container load the host WireGuard
# module when the kernel does not have it built in.
RUN apk add --no-cache \
    python3 \
    py3-flask \
    py3-yaml \
    py3-waitress \
    bash \
    ca-certificates \
    haproxy \
    wireguard-tools \
    iproute2 \
    kmod

WORKDIR /app

COPY app.py audit.py catalog.py detect.py i18n.py proxy.py reachability.py scan.py targets.py udp.py serve.py state.py sync.py vps.py wireguard.py ./
COPY i18n ./i18n
COPY templates ./templates
COPY static ./static

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8081

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8081/api/health >/dev/null || exit 1

ENTRYPOINT ["/entrypoint.sh"]
