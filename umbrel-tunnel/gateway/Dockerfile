FROM alpine:3.20

# wg-quick is a bash script, so bash is required (Alpine's /bin/sh is ash).
RUN apk add --no-cache \
    python3 \
    py3-flask \
    bash \
    haproxy \
    wireguard-tools \
    iproute2

WORKDIR /app

COPY app.py catalog.py detect.py docker_api.py proxy.py state.py sync.py vps.py wireguard.py ./
COPY templates ./templates
COPY static ./static

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8081

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8081/api/health >/dev/null || exit 1

ENTRYPOINT ["/entrypoint.sh"]
