FROM alpine:3.19

RUN apk add --no-cache \
    wireguard-tools \
    haproxy \
    python3 \
    py3-pip \
    py3-flask \
    py3-netifaces \
    bind-tools \
    iproute2 \
    iptables \
    openrc

WORKDIR /app

COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

COPY app.py .
COPY templates templates/

ENTRYPOINT ["/entrypoint.sh"]
