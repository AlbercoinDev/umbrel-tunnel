"""Catálogo de servicios conocidos de Umbrel.

La detección por Docker es la fuente principal. Este catálogo solo aporta
nombres legibles, descripciones y el aviso de "sensible" para los puertos más
habituales. Cualquier app desconocida se sigue listando con sus puertos.
"""

CATALOG = {
    "bitcoin": {
        "name": "Bitcoin Core",
        "ip_vars": ["APP_BITCOIN_NODE_IP"],
        "services": [
            {
                "name": "Bitcoin Node panel",
                "port": 3000,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Panel web de la app Bitcoin Node.",
            },
            {
                "name": "Bitcoin P2P",
                "port": 8333,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Red peer-to-peer de Bitcoin.",
                "service": "app",
                "extra": True,
                "port_vars": ["APP_BITCOIN_P2P_PORT"],
            },
            {
                "name": "Bitcoin RPC",
                "port": 8332,
                "protocol": "tcp",
                "sensitive": True,
                "description": "RPC de Bitcoin. Protégelo con credenciales fuertes.",
                "service": "app",
                "extra": True,
                "port_vars": ["APP_BITCOIN_RPC_PORT"],
            },
            {
                "name": "Bitcoin P2P whitebind",
                "port": 8335,
                "protocol": "tcp",
                "sensitive": True,
                "description": "Listener P2P con permisos de confianza para apps internas. No lo publiques en Internet.",
                "service": "app",
                "extra": True,
                "port_vars": ["APP_BITCOIN_P2P_WHITEBIND_PORT"],
            },
            {
                "name": "Bitcoin ZMQ rawblock",
                "port": 28332,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Flujo ZMQ de bloques crudos para indexadores.",
                "service": "app",
                "extra": True,
                "port_vars": ["APP_BITCOIN_ZMQ_RAWBLOCK_PORT"],
            },
            {
                "name": "Bitcoin ZMQ rawtx",
                "port": 28333,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Flujo ZMQ de transacciones crudas para indexadores.",
                "service": "app",
                "extra": True,
                "port_vars": ["APP_BITCOIN_ZMQ_RAWTX_PORT"],
            },
            {
                "name": "Bitcoin ZMQ hashblock",
                "port": 28334,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Flujo ZMQ con el hash de cada bloque.",
                "service": "app",
                "extra": True,
                "port_vars": ["APP_BITCOIN_ZMQ_HASHBLOCK_PORT"],
            },
            {
                "name": "Bitcoin ZMQ sequence",
                "port": 28335,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Flujo ZMQ de secuencias de mempool y bloques.",
                "service": "app",
                "extra": True,
                "port_vars": ["APP_BITCOIN_ZMQ_SEQUENCE_PORT"],
            },
            {
                "name": "Bitcoin ZMQ hashtx",
                "port": 28336,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Flujo ZMQ con el hash de cada transacción.",
                "service": "app",
                "extra": True,
                "port_vars": ["APP_BITCOIN_ZMQ_HASHTX_PORT"],
            },
        ],
    },
    "bitcoin-knots": {
        "name": "Bitcoin Knots",
        "ip_vars": ["APP_BITCOIN_KNOTS_NODE_IP"],
        "services": [
            {
                "name": "Bitcoin Knots panel",
                "port": 3000,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Panel web de Bitcoin Knots.",
            },
            {
                "name": "Bitcoin Knots P2P",
                "port": 9333,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Red peer-to-peer de Bitcoin Knots.",
                "service": "app",
                "extra": True,
                "port_vars": ["APP_BITCOIN_KNOTS_P2P_PORT"],
            },
            {
                "name": "Bitcoin Knots RPC",
                "port": 9332,
                "protocol": "tcp",
                "sensitive": True,
                "description": "RPC de Bitcoin Knots. Protégelo con credenciales fuertes.",
                "service": "app",
                "extra": True,
                "port_vars": ["APP_BITCOIN_KNOTS_RPC_PORT"],
            },
            {
                "name": "Bitcoin Knots P2P whitebind",
                "port": 9335,
                "protocol": "tcp",
                "sensitive": True,
                "description": "Listener P2P con permisos de confianza para apps internas. No lo publiques en Internet.",
                "service": "app",
                "extra": True,
                "port_vars": ["APP_BITCOIN_KNOTS_P2P_WHITEBIND_PORT"],
            },
            {
                "name": "Bitcoin Knots ZMQ rawblock",
                "port": 48332,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Flujo ZMQ de bloques crudos para indexadores.",
                "service": "app",
                "extra": True,
                "port_vars": ["APP_BITCOIN_KNOTS_ZMQ_RAWBLOCK_PORT"],
            },
            {
                "name": "Bitcoin Knots ZMQ rawtx",
                "port": 48333,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Flujo ZMQ de transacciones crudas para indexadores.",
                "service": "app",
                "extra": True,
                "port_vars": ["APP_BITCOIN_KNOTS_ZMQ_RAWTX_PORT"],
            },
            {
                "name": "Bitcoin Knots ZMQ hashblock",
                "port": 48334,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Flujo ZMQ con el hash de cada bloque.",
                "service": "app",
                "extra": True,
                "port_vars": ["APP_BITCOIN_KNOTS_ZMQ_HASHBLOCK_PORT"],
            },
            {
                "name": "Bitcoin Knots ZMQ sequence",
                "port": 48335,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Flujo ZMQ de secuencias de mempool y bloques.",
                "service": "app",
                "extra": True,
                "port_vars": ["APP_BITCOIN_KNOTS_ZMQ_SEQUENCE_PORT"],
            },
            {
                "name": "Bitcoin Knots ZMQ hashtx",
                "port": 48336,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Flujo ZMQ con el hash de cada transacción.",
                "service": "app",
                "extra": True,
                "port_vars": ["APP_BITCOIN_KNOTS_ZMQ_HASHTX_PORT"],
            },
        ],
    },
    "lightning": {
        "name": "Lightning Network",
        "ip_vars": ["APP_LIGHTNING_NODE_IP"],
        "services": [
            {
                "name": "Lightning Node panel",
                "port": 3006,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Panel web de la app Lightning Node.",
            },
            {
                "name": "Lightning P2P",
                "port": 9735,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Conexiones entre nodos Lightning.",
                "service": "lnd",
                "extra": True,
                "port_vars": ["APP_LIGHTNING_P2P_PORT"],
            },
            {
                "name": "LND gRPC",
                "port": 10009,
                "protocol": "tcp",
                "sensitive": True,
                "description": "API gRPC de LND. Requiere macaroon.",
                "service": "lnd",
                "extra": True,
                "port_vars": ["APP_LIGHTNING_GRPC_PORT"],
            },
            {
                "name": "LND REST",
                "port": 8080,
                "protocol": "tcp",
                "sensitive": True,
                "description": "API REST de LND. Requiere macaroon.",
                "service": "lnd",
                "extra": True,
                "port_vars": ["APP_LIGHTNING_REST_PORT"],
            },
        ],
    },
    "electrs": {
        "name": "Electrs",
        "ip_vars": ["APP_ELECTRS_NODE_IP", "APP_ELECTRS_IP"],
        "services": [
            {
                "name": "Electrs panel",
                "port": 3006,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Panel web de Electrs.",
            },
            {
                "name": "Electrum Server",
                "port": 50001,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Servidor Electrum TCP para monederos Bitcoin.",
                "service": "electrs",
                "extra": True,
                "port_vars": ["APP_ELECTRS_NODE_PORT"],
            },
        ],
    },
    "mempool": {
        "name": "Mempool",
        "ip_vars": ["APP_MEMPOOL_IP", "APP_MEMPOOL_API_IP"],
        "services": [
            {
                "name": "Mempool Web",
                "port": 3006,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Explorador de bloques y mempool.",
                "port_vars": ["APP_MEMPOOL_PORT"],
            },
            {
                "name": "Mempool API",
                "port": 8999,
                "protocol": "tcp",
                "sensitive": False,
                "description": "API HTTP de Mempool.",
                "service": "api",
                "extra": True,
                "port_vars": ["APP_MEMPOOL_API_PORT"],
            },
        ],
    },
    "btc-rpc-explorer": {
        "name": "BTC RPC Explorer",
        "ip_vars": ["APP_BTC_RPC_EXPLORER_IP"],
        "services": [
            {
                "name": "BTC RPC Explorer",
                "port": 3002,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Explorador de bloques de Bitcoin.",
                "port_vars": ["APP_BTC_RPC_EXPLORER_PORT"],
            }
        ],
    },
    "lnbits": {
        "name": "LNbits",
        "ip_vars": ["APP_LNBITS_IP"],
        "services": [
            {
                "name": "LNbits",
                "port": 5000,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Servidor de cuentas Lightning.",
                "port_vars": ["APP_LNBITS_PORT"],
            }
        ],
    },
    "thunderhub": {
        "name": "ThunderHub",
        "ip_vars": ["APP_THUNDERHUB_IP"],
        "services": [
            {
                "name": "ThunderHub",
                "port": 3000,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Panel de control de LND.",
                "port_vars": ["APP_THUNDERHUB_PORT"],
            }
        ],
    },
    "nextcloud": {
        "name": "Nextcloud",
        "ip_vars": ["APP_NEXTCLOUD_IP"],
        "services": [
            {
                "name": "Nextcloud",
                "port": 80,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Nube privada.",
                "port_vars": ["APP_NEXTCLOUD_PORT"],
            }
        ],
    },
    "immich": {
        "name": "Immich",
        "ip_vars": ["APP_IMMICH_IP"],
        "services": [
            {
                "name": "Immich",
                "port": 2283,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Fotos y vídeos autohospedados.",
                "port_vars": ["APP_IMMICH_PORT"],
            }
        ],
    },
    "photoprism": {
        "name": "PhotoPrism",
        "ip_vars": ["APP_PHOTOPRISM_IP"],
        "services": [
            {
                "name": "PhotoPrism",
                "port": 2342,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Galería de fotos con IA.",
                "port_vars": ["APP_PHOTOPRISM_PORT"],
            }
        ],
    },
    "jellyfin": {
        "name": "Jellyfin",
        "ip_vars": ["APP_JELLYFIN_IP"],
        "services": [
            {
                "name": "Jellyfin",
                "port": 8096,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Servidor multimedia.",
                "port_vars": ["APP_JELLYFIN_PORT"],
            }
        ],
    },
    "plex": {
        "name": "Plex",
        "ip_vars": ["APP_PLEX_IP"],
        "services": [
            {
                "name": "Plex",
                "port": 32400,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Servidor multimedia Plex.",
                "port_vars": ["APP_PLEX_PORT"],
            }
        ],
    },
    "syncthing": {
        "name": "Syncthing",
        "ip_vars": ["APP_SYNCTHING_IP"],
        "services": [
            {
                "name": "Syncthing Web",
                "port": 8384,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Interfaz web de Syncthing.",
                "port_vars": ["APP_SYNCTHING_PORT"],
            },
            {
                "name": "Syncthing Sync",
                "port": 22000,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Sincronización entre dispositivos.",
                "port_vars": ["APP_SYNCTHING_SYNC_PORT"],
            },
        ],
    },
    "paperless": {
        "name": "Paperless-ngx",
        "ip_vars": ["APP_PAPERLESS_NGX_IP"],
        "services": [
            {
                "name": "Paperless-ngx",
                "port": 8000,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Gestión documental.",
                "port_vars": ["APP_PAPERLESS_NGX_PORT"],
            }
        ],
    },
    "home-assistant": {
        "name": "Home Assistant",
        "ip_vars": ["APP_HOME_ASSISTANT_IP"],
        "services": [
            {
                "name": "Home Assistant",
                "port": 8123,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Domótica.",
                "port_vars": ["APP_HOME_ASSISTANT_PORT"],
            }
        ],
    },
    "node-red": {
        "name": "Node-RED",
        "ip_vars": ["APP_NODE_RED_IP"],
        "services": [
            {
                "name": "Node-RED",
                "port": 1880,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Automatización visual.",
                "port_vars": ["APP_NODE_RED_PORT"],
            }
        ],
    },
    "node-red-standalone": {
        "name": "Node-RED",
        "services": [
            {
                "name": "Node-RED",
                "port": 1881,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Automatización visual.",
            }
        ],
    },
    "adguard-home": {
        "name": "AdGuard Home",
        "services": [
            {
                "name": "AdGuard Home",
                "port": 8095,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Panel web de AdGuard Home.",
                "service": "server",
            },
            {
                "name": "AdGuard DNS",
                "port": 53,
                "protocol": "tcp",
                "sensitive": True,
                "description": "DNS de AdGuard Home por TCP.",
                "service": "server",
                "extra": True,
            },
            {
                "name": "AdGuard DNS",
                "port": 53,
                "protocol": "udp",
                "sensitive": True,
                "description": "DNS de AdGuard Home por UDP.",
                "service": "server",
                "extra": True,
            },
        ],
    },
    "technitium-dns": {
        "name": "Technitium DNS",
        "services": [
            {
                "name": "Technitium DNS",
                "port": 5380,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Panel web de Technitium DNS.",
                "service": "dns-server",
            },
            {
                "name": "Technitium DNS",
                "port": 53,
                "protocol": "tcp",
                "sensitive": True,
                "description": "DNS de Technitium por TCP.",
                "service": "dns-server",
                "extra": True,
            },
            {
                "name": "Technitium DNS",
                "port": 53,
                "protocol": "udp",
                "sensitive": True,
                "description": "DNS de Technitium por UDP.",
                "service": "dns-server",
                "extra": True,
            },
        ],
    },
    "openthread-border-router": {
        "name": "OpenThread Border Router",
        "services": [
            {
                "name": "OpenThread setup",
                "port": 7586,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Asistente de configuración de OpenThread.",
                "service": "setup",
            },
            {
                "name": "OpenThread web",
                "port": 7587,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Panel web de OpenThread Border Router.",
                "service": "server",
                "extra": True,
            },
            {
                "name": "OpenThread REST",
                "port": 8083,
                "protocol": "tcp",
                "sensitive": True,
                "description": "API REST de OpenThread Border Router.",
                "service": "server",
                "extra": True,
            },
        ],
    },
    "music-assistant": {
        "name": "Music Assistant",
        "services": [
            {
                "name": "Music Assistant",
                "port": 8896,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Panel web de Music Assistant.",
                "service": "web",
            },
            {
                "name": "Music Assistant streams",
                "port": 8078,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Servidor de streaming de Music Assistant.",
                "service": "web",
                "extra": True,
            },
            {
                "name": "Music Assistant Sendspin",
                "port": 8927,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Servicio Sendspin de Music Assistant.",
                "service": "web",
                "extra": True,
            },
        ],
    },
    "vaultwarden": {
        "name": "Vaultwarden",
        "ip_vars": ["APP_VAULTWARDEN_IP"],
        "services": [
            {
                "name": "Vaultwarden",
                "port": 80,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Gestor de contraseñas compatible con Bitwarden.",
                "port_vars": ["APP_VAULTWARDEN_PORT"],
            }
        ],
    },
    "gitea": {
        "name": "Gitea",
        "ip_vars": ["APP_GITEA_IP"],
        "services": [
            {
                "name": "Gitea Web",
                "port": 3000,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Servidor Git.",
                "port_vars": ["APP_GITEA_PORT"],
            },
            {
                "name": "Gitea SSH",
                "port": 22,
                "protocol": "tcp",
                "sensitive": True,
                "description": "SSH de Gitea. Usa un puerto público distinto del 22 del VPS.",
                "port_vars": ["APP_GITEA_SSH_PORT"],
            },
        ],
    },
    "code-server": {
        "name": "code-server",
        "ip_vars": ["APP_CODE_SERVER_IP"],
        "services": [
            {
                "name": "code-server",
                "port": 8080,
                "protocol": "tcp",
                "sensitive": True,
                "description": "VS Code en el navegador.",
                "port_vars": ["APP_CODE_SERVER_PORT"],
            }
        ],
    },
    "n8n": {
        "name": "n8n",
        "ip_vars": ["APP_N8N_IP"],
        "services": [
            {
                "name": "n8n",
                "port": 5678,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Automatización de flujos.",
                "port_vars": ["APP_N8N_PORT"],
            }
        ],
    },
    "ollama": {
        "name": "Ollama",
        "ip_vars": ["APP_OLLAMA_IP"],
        "services": [
            {
                "name": "Ollama API",
                "port": 11434,
                "protocol": "tcp",
                "sensitive": True,
                "description": "API de modelos de lenguaje. Sin autenticación por defecto.",
                "port_vars": ["APP_OLLAMA_PORT"],
            }
        ],
    },
    "open-webui": {
        "name": "Open WebUI",
        "ip_vars": ["APP_OPEN_WEBUI_IP"],
        "services": [
            {
                "name": "Open WebUI",
                "port": 8080,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Interfaz web para modelos de lenguaje.",
                "port_vars": ["APP_OPEN_WEBUI_PORT"],
            }
        ],
    },
    "grafana": {
        "name": "Grafana",
        "ip_vars": ["APP_GRAFANA_IP"],
        "services": [
            {
                "name": "Grafana",
                "port": 3000,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Cuadros de mando y métricas.",
                "port_vars": ["APP_GRAFANA_PORT"],
            }
        ],
    },
    "prometheus": {
        "name": "Prometheus",
        "ip_vars": ["APP_PROMETHEUS_IP"],
        "services": [
            {
                "name": "Prometheus",
                "port": 9090,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Recolección de métricas.",
                "port_vars": ["APP_PROMETHEUS_PORT"],
            }
        ],
    },
    "uptime-kuma": {
        "name": "Uptime Kuma",
        "ip_vars": ["APP_UPTIME_KUMA_IP"],
        "services": [
            {
                "name": "Uptime Kuma",
                "port": 3001,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Monitorización de servicios.",
                "port_vars": ["APP_UPTIME_KUMA_PORT"],
            }
        ],
    },
    "transmission": {
        "name": "Transmission",
        "ip_vars": ["APP_TRANSMISSION_IP"],
        "services": [
            {
                "name": "Transmission Web",
                "port": 9091,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Interfaz web de Transmission.",
                "port_vars": ["APP_TRANSMISSION_PORT"],
            },
            {
                "name": "Transmission P2P",
                "port": 51413,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Puerto de pares de BitTorrent.",
                "port_vars": ["APP_TRANSMISSION_PEER_PORT"],
            },
        ],
    },
    "qbittorrent": {
        "name": "qBittorrent",
        "ip_vars": ["APP_QBITTORRENT_IP"],
        "services": [
            {
                "name": "qBittorrent Web",
                "port": 8080,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Interfaz web de qBittorrent.",
                "port_vars": ["APP_QBITTORRENT_PORT"],
            },
            {
                "name": "qBittorrent P2P",
                "port": 6881,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Puerto de pares de BitTorrent.",
                "port_vars": ["APP_QBITTORRENT_PEER_PORT"],
            },
        ],
    },
    "pi-hole": {
        "name": "Pi-hole",
        "ip_vars": ["APP_PIHOLE_IP"],
        "services": [
            {
                "name": "Pi-hole Web",
                "port": 80,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Interfaz web de Pi-hole.",
                "port_vars": ["APP_PIHOLE_PORT"],
            },
            {
                "name": "Pi-hole Web",
                "port": 8082,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Interfaz web de Pi-hole (versiones recientes).",
            },
            {
                "name": "Pi-hole DNS",
                "port": 53,
                "protocol": "tcp",
                "sensitive": True,
                "description": "DNS de Pi-hole por TCP.",
                "service": "server",
                "extra": True,
                "port_vars": ["APP_PIHOLE_DNS_PORT"],
            },
            {
                "name": "Pi-hole DNS",
                "port": 53,
                "protocol": "udp",
                "sensitive": True,
                "description": "DNS de Pi-hole por UDP.",
                "service": "server",
                "extra": True,
                "port_vars": ["APP_PIHOLE_DNS_PORT"],
            },
        ],
    },
    "wordpress": {
        "name": "WordPress",
        "ip_vars": ["APP_WORDPRESS_IP"],
        "services": [
            {
                "name": "WordPress",
                "port": 80,
                "protocol": "tcp",
                "sensitive": False,
                "description": "Sitio WordPress.",
                "port_vars": ["APP_WORDPRESS_PORT"],
            }
        ],
    },
    "portainer": {
        "name": "Portainer",
        "ip_vars": ["APP_PORTAINER_IP"],
        "services": [
            {
                "name": "Portainer",
                "port": 9000,
                "protocol": "tcp",
                "sensitive": True,
                "description": "Administración de Docker.",
                "port_vars": ["APP_PORTAINER_PORT"],
            }
        ],
    },
}

# Servicios del propio UmbrelOS (no son contenedores de apps).
# Se comprueban contra la IP del host y se marcan como sensibles.
SYSTEM_SERVICES = [
    {
        "id": "ssh",
        "name": "UmbrelOS SSH",
        "port": 22,
        "protocol": "tcp",
        "sensitive": True,
        "description": "Acceso SSH al host. No uses el puerto 22 del VPS: elige otro público.",
    },
    {
        "id": "umbrel-dashboard",
        "name": "UmbrelOS dashboard",
        "port": 80,
        "protocol": "tcp",
        "sensitive": True,
        "description": "Interfaz principal de Umbrel. Exponerla da acceso al panel de administración.",
    },
    {
        "id": "umbrel-dashboard-https",
        "name": "UmbrelOS dashboard (HTTPS)",
        "port": 443,
        "protocol": "tcp",
        "sensitive": True,
        "description": "Interfaz de Umbrel por HTTPS. Exponerla da acceso al panel de administración.",
    },
]


APP_ALIASES = {
    # Historic/community app ids that differ from the current Umbrel id.
    "pihole": "pi-hole",
    "paperless-ngx": "paperless",
}


def _catalog_entry(app_id):
    entry = CATALOG.get(app_id)
    if entry is not None:
        return entry
    alias = APP_ALIASES.get(app_id)
    return CATALOG.get(alias) if alias else None


def app_name(app_id):
    entry = _catalog_entry(app_id)
    if entry:
        return entry["name"]
    return app_id


def service_for(app_id, port):
    """Devuelve metadatos del catálogo para app_id/puerto, o None."""
    entry = _catalog_entry(app_id)
    if not entry:
        return None
    for svc in entry["services"]:
        if svc["port"] == port:
            return svc
    return None


def port_defaults(app_id):
    """Mapa ``VARIABLE_DE_ENTORNO -> puerto`` conocido para una app.

    Se usa como respaldo cuando ``exports.sh`` no está disponible o no se pudo
    leer (por ejemplo, en tests o tras una instalación parcial). Compose usa
    esas variables para interpolar ``ports``, así que sin este mapa los puertos
    de Bitcoin/Electrs desaparecen de la detección.
    """
    entry = _catalog_entry(app_id)
    if not entry:
        return {}
    result: dict[str, int] = {}
    for svc in entry.get("services", []):
        try:
            port = int(svc["port"])
        except (KeyError, TypeError, ValueError):
            continue
        for var in svc.get("port_vars", []) or []:
            result[str(var)] = port
    return result


def extra_services(app_id, values=None):
    """Puertos conocidos que no siempre aparecen en ``ports``/``expose``.

    ``values`` es el entorno resuelto de la app (``exports.sh`` + valores por
    defecto). Solo se devuelven entradas marcadas con ``extra`` y con un
    servicio de Compose asociado, para no inventar puertos en contenedores
    arbitrarios.
    """
    entry = _catalog_entry(app_id)
    if not entry:
        return []
    resolved = values or {}
    result: list[dict] = []
    for svc in entry.get("services", []):
        if not svc.get("extra") or not svc.get("service"):
            continue
        port = svc.get("port")
        for var in svc.get("port_vars", []) or []:
            raw = resolved.get(str(var))
            if raw in (None, ""):
                continue
            try:
                port = int(str(raw).strip())
            except (TypeError, ValueError):
                continue
            break
        try:
            port = int(port)
        except (TypeError, ValueError):
            continue
        if not 1 <= port <= 65535:
            continue
        result.append({**svc, "port": port})
    return result


def ip_vars(app_id):
    entry = _catalog_entry(app_id)
    if entry:
        return list(entry.get("ip_vars", []))
    return []
