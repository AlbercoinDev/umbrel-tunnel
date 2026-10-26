# umbrel-tunnel

Expón servicios de tu Umbrel a través de un VPS con IP fija usando un túnel
WireGuard. La app de Umbrel detecta las aplicaciones instaladas y los servicios
de UmbrelOS, deja elegir qué puertos abrir y sincroniza los forwards públicos
con el VPS. La API del VPS solo escucha dentro del túnel y está protegida con un
token Bearer.

```
Internet ──► VPS (IP fija) ──► wg0 ──► Umbrel ──► HAProxy ──► app/contenedor
             DNAT :8333       túnel    10.0.0.2    :20000      app_web_1:3000
             nftables         10.0.0.1
```

- **VPS**: un único binario Go estático + systemd, WireGuard en el kernel y
  nftables. Sin Docker ni Python. Pensado para 128–256 MB de RAM.
- **Umbrel**: app con gateway en Flask/waitress, detección de apps leyendo
  `app-data` en modo solo lectura (sin socket de Docker), HAProxy para el proxy
  TCP local y `wg-quick` para el túnel.
- **Sin DDNS ni QR**: el VPS tiene IP fija y el emparejamiento es un código
  `ut1.…` que se pega en la app.
- **Bilingüe**: interfaz en español por defecto e inglés opcional. En la
  primera visita se detecta el idioma del navegador/UmbrelOS.

## Requisitos

**VPS**

- Debian 12/13 o Ubuntu 22.04/24.04+ (`amd64` o `arm64`).
- Acceso root (o `sudo`).
- IP pública fija y salida a Internet.
- Puertos: el que elijas para WireGuard (por defecto `51820/udp`) y los puertos
  públicos que quieras exponer. El `22/tcp` del VPS queda reservado para SSH.

**Umbrel**

- UmbrelOS con Docker.
- La app se instala desde la Community App Store
  `AlbercoinDev/Umbrel-AppStore-Albercoin`. Para desarrollo, copia la carpeta
  `umbrel-tunnel/` a `app-data/albercoin-store-umbrel-tunnel/`.

## Flujo recomendado: primero la app, después el VPS

La app genera las claves y el token, y te muestra el comando exacto que debes
ejecutar en el VPS. No tienes que copiar claves a mano.

1. Instala **Umbrel Tunnel** en Umbrel (ver
   [Instalación de la app](#instalación-de-la-app-en-umbrel)).
2. Abre la app. Si aún no hay VPS vinculado, la pestaña **Conexión** muestra el
   asistente y te pide la **IP pública fija** del VPS.
3. Pulsa **Generar comando de instalación**. La app crea su par de claves
   WireGuard, un token nuevo y muestra un comando de una línea.
4. Copia el comando y ejecútalo en el VPS como root.
5. Al terminar, el instalador imprime un bloque de emparejamiento con
   `Código: ut1.…` y lo guarda en `/root/umbrel-tunnel-pairing.txt`.
6. Vuelve a la app, pega el **bloque completo** y pulsa **Vincular VPS**.
7. La app comprueba que el código coincide con el comando que generó, levanta
   WireGuard, registra su clave pública en el VPS y queda lista para abrir
   puertos.

## Instalación del VPS

### Opción A: comando generado por la app (recomendada)

El comando tiene esta forma (la app rellena todos los valores):

```bash
curl -fsSL https://raw.githubusercontent.com/AlbercoinDev/umbrel-tunnel/main/vps/install.sh \
  | sudo bash -s -- \
      --endpoint 203.0.113.10 \
      --token '<TOKEN>' \
      --umbrel-pubkey '<CLAVE_PUBLICA_DE_LA_APP>' \
      --subnet 10.0.0.0/24 \
      --server-ip 10.0.0.1 \
      --umbrel-ip 10.0.0.2 \
      --api-port 8080 \
      --wg-port 51820 \
      --mtu 1420 \
      --binary-base https://github.com/AlbercoinDev/umbrel-tunnel/releases/latest/download
```

`--binary-base` descarga `umbrel-tunnel-linux-amd64` o
`umbrel-tunnel-linux-arm64` según la arquitectura del VPS.

### Opción B: desde este repositorio (desarrollo)

En tu máquina local:

```bash
cd vps
./scripts/push.sh root@203.0.113.10 --endpoint 203.0.113.10
```

`push.sh` compila `amd64`/`arm64`, copia el tarball por SSH y ejecuta el
instalador. Si `sudo` pide contraseña, la sesión usa TTY para que puedas
escribirla. Opciones útiles:

```bash
./scripts/push.sh root@vps --endpoint 203.0.113.10 --wg-port 51820
./scripts/push.sh root@vps --ssh-port 2222 --ssh-key ~/.ssh/vps
./scripts/push.sh root@vps --purge          # desinstala y borra datos
```

### Opción C: tarball manual

```bash
cd vps
make dist
scp dist/umbrel-tunnel-1.0.0-linux-amd64.tar.gz root@203.0.113.10:/tmp/
ssh root@203.0.113.10
tar -xzf /tmp/umbrel-tunnel-1.0.0-linux-amd64.tar.gz -C /tmp
cd /tmp/umbrel-tunnel-1.0.0-linux-amd64
sudo ./install.sh --endpoint 203.0.113.10
```

### Qué hace el instalador

1. Comprueba sistema, arquitectura, systemd, Internet, RAM/disco y puertos.
2. Instala solo lo que falta (`wireguard`, `wireguard-tools`, `nftables`, etc.).
3. Copia el binario a `/usr/local/bin/umbrel-tunnel`.
4. Instala las unidades `wg-quick@wg0`, `umbrel-tunnel-firewall` y `umbrel-tunnel`.
5. Crea claves del servidor, token, configuración y reglas de firewall. No crea
   ninguna clave privada de Umbrel: la app genera la suya y registra su clave
   pública por la API.
6. Verifica que la API responde en `10.0.0.1:8080` y que escucha solo en el túnel.
7. Imprime el bloque de emparejamiento y lo guarda en
   `/root/umbrel-tunnel-pairing.txt` (permisos `600`). Pega ese bloque en la
   app para vincular el VPS.

Opciones principales:

```text
--endpoint IP        IP pública fija (si se omite, se detecta)
--token TOKEN        token de API (la app lo genera; si se omite, se genera)
--wg-port PORT       puerto UDP de WireGuard (51820)
--api-port PORT      puerto de la API dentro del túnel (8080)
--subnet CIDR        subred del túnel (10.0.0.0/24)
--server-ip IP       IP del VPS dentro del túnel (10.0.0.1)
--umbrel-ip IP       IP de Umbrel dentro del túnel (10.0.0.2)
--mtu N              MTU del túnel (1420)
--umbrel-pubkey KEY  pre-registra la clave pública de Umbrel (la app la genera)
--public-api         expone la API fuera del túnel (no recomendado)
--binary URL|RUTA    binario a instalar
--binary-base URL    base de descarga; añade /umbrel-tunnel-linux-$ARCH
--force              sustituye configuración existente (hace backup de wg0.conf)
--no-start           instala sin arrancar
--dry-run            muestra lo que haría
--uninstall [--purge] desinstala (y borra configuración con --purge)
```

Reejecutar el instalador es seguro: conserva la configuración y las claves
existentes salvo que uses `--force`.

## Instalación de la app en Umbrel

### Community App Store

1. En UmbrelOS: **App Store → … → Community App Stores → Add store**.
2. Pega la URL de la tienda:
   `https://github.com/AlbercoinDev/Umbrel-AppStore-Albercoin`.
   La app vive en la carpeta `albercoin-store-umbrel-tunnel/` de esa tienda
   (`albercoin-store`).
3. Instala **Umbrel Tunnel**. La imagen del gateway se publica en
   `ghcr.io/albercoindev/umbrel-tunnel-gateway` y el compose la fija por digest
   (`@sha256:…`) para que cada instalación use exactamente la misma imagen.

> El repositorio `AlbercoinDev/umbrel-tunnel` contiene el código, la
> documentación y las releases del plano de control del VPS. La tienda
> `AlbercoinDev/Umbrel-AppStore-Albercoin` es la que se añade a UmbrelOS.

### Emparejar Umbrel

Sigue el [flujo recomendado](#flujo-recomendado-primero-la-app-después-el-vps):

1. Instala la app **Umbrel Tunnel** en Umbrel.
2. Abre la app y ve a **Conexión**. Introduce la IP pública del VPS y pulsa
   **Generar comando de instalación**.
3. Ejecuta ese comando en el VPS.
4. Pega el bloque que imprime el instalador en la app y pulsa **Vincular VPS**.

El código `ut1` incluye la URL de la API (`http://10.0.0.1:8080`), el token, el
endpoint del VPS, la clave pública del servidor, la IP de Umbrel en el túnel, la
subred y el MTU. **No incluye ninguna clave privada de WireGuard**: la app crea
su par de claves y registra la pública en el VPS con `POST/PUT /api/peers`.

La app valida que el código coincida con el comando que generó (token, endpoint,
API, subred, IP y MTU), que la URL de la API pertenezca a la subred del túnel y
que la subred no solape con la red de Umbrel (`NETWORK_IP`, por defecto
`10.21.0.0/16`). Si el VPS se reinstala con otro token, genera un comando nuevo
con **Cambiar VPS**.

### Emparejamiento manual

Si prefieres no usar el código, o quieres rotar claves:

```bash
# En el VPS, opcionalmente con la clave pública de Umbrel ya conocida:
umbrel-tunnel init --endpoint 203.0.113.10 --umbrel-pubkey "<CLAVE_PUBLICA_UMBREL>"

# O añade un peer después:
umbrel-tunnel peer add --name umbrel --ip 10.0.0.2 --pubkey "<CLAVE_PUBLICA_UMBREL>"
```

En la app, pestaña **Conexión → Emparejamiento manual**: introduce endpoint,
clave pública del servidor, IP de Umbrel, subred y MTU. La app genera la clave
local, aplica la configuración y muestra la clave pública que debe registrarse
en el VPS. Si la app ya está emparejada por API/token, el registro es
automático.

## Uso

- **Servicios**: lista detectada de apps y servicios de UmbrelOS. Elige el
  puerto público y pulsa **Abrir**. El VPS crea el DNAT y la app configura
  HAProxy en el lado de Umbrel.
- **Puertos abiertos**: estado de cada exposición, activar/desactivar, cambiar
  el puerto público o cerrarlo.
- **Conexión**: estado del túnel y del handshake, configuración de WireGuard
  (redactada), emparejamiento manual y rotación de claves.
- **Avanzado**: URL/token de la API, intervalo de sincronización y servicios
  manuales.

Los servicios del sistema (SSH, panel de UmbrelOS por HTTP/HTTPS) se marcan como
**sistema** y **sensible**. El puerto público `22` está bloqueado para no pisar
el SSH del VPS; para SSH de Umbrel se propone `2222`.

La sincronización es declarativa: la app compara lo que quieres exponer con los
forwards del VPS y crea, actualiza o elimina lo necesario. Se ejecuta al cambiar
algo y cada `sync_interval` segundos (30 por defecto).

### Detección de servicios

La app **no monta el socket de Docker**. Lee, en modo solo lectura:

- `${UMBREL_ROOT}/app-data/<app-id>/umbrel-app.yml`
- `${UMBREL_ROOT}/app-data/<app-id>/docker-compose.yml`
- `${UMBREL_ROOT}/app-data/<app-id>/app-gateway.json` (destino resuelto por umbreld)
- `${UMBREL_ROOT}/app-data/<app-id>/exports.sh` (solo se analiza con regex; nunca se ejecuta)

Usa los nombres DNS de Docker (`<app-id>_<servicio>_1`) como destino, de modo
que el proxy sigue funcionando aunque cambie la IP del contenedor. Los servicios
del host (SSH/panel) se detectan contra la puerta de enlace de la red Docker. Si
una app no se detecta, añade un servicio manual en **Avanzado**.

## CLI del VPS

```bash
umbrel-tunnel serve                      # API (lo arranca systemd)
umbrel-tunnel init [opciones]            # configuración, claves, token
umbrel-tunnel pair [--json] [--rotate-token]
umbrel-tunnel peer list
umbrel-tunnel peer add --name N --ip 10.0.0.3 [--pubkey KEY]
umbrel-tunnel peer rm <id>
umbrel-tunnel peer config <id>
umbrel-tunnel forward list
umbrel-tunnel forward add --name web --public-port 8080 --target-ip 10.0.0.2 \
  --target-port 20000 [--protocol tcp|udp] [--disabled]
umbrel-tunnel forward rm <id>
umbrel-tunnel forward enable|disable <id>
umbrel-tunnel token show|rotate
umbrel-tunnel doctor [--json]
umbrel-tunnel update --from URL|PATH [--sha256 HEX] [--no-restart]
umbrel-tunnel backup [--output FILE]
umbrel-tunnel restore --from FILE [--force]
umbrel-tunnel uninstall [--purge]
umbrel-tunnel version
```

La CLI es útil para abrir puertos **UDP** (la app de Umbrel solo gestiona TCP)
y para diagnósticos por SSH.

## API del VPS

Escucha en `10.0.0.1:8080` (solo túnel). Autenticación `Authorization: Bearer <token>`.

| Método | Ruta | Descripción |
| --- | --- | --- |
| GET | `/health` | Estado básico, sin auth |
| GET | `/api/status` | Versión, peers, forwards, handshakes |
| GET/POST | `/api/peers` | Lista/crea peers |
| PUT | `/api/peers/{id}` | Rota la clave pública / endpoint de un peer |
| DELETE | `/api/peers/{id}` | Elimina peer |
| GET | `/api/peers/{id}/config` | Configuración de un peer creado por el VPS (409 en modo manual) |
| GET/POST | `/api/forwards` | Lista/crea forwards |
| PATCH/DELETE | `/api/forwards/{id}` | Actualiza/elimina forward |
| POST | `/api/token/rotate` | Rota el token |

Un forward usa `public_port`:

```json
{
  "name": "umbrel:mempool:abc123",
  "public_port": 3006,
  "target_ip": "10.0.0.2",
  "target_port": 20000,
  "protocol": "tcp",
  "enabled": true
}
```

### Panel web del VPS

Desde un equipo conectado al túnel abre `http://10.0.0.1:8080`. La página pide
el token (`umbrel-tunnel token show`) y lo guarda solo en `sessionStorage`; no hay
formulario de login persistente ni cookie. Permite ver estado, peers,
handshakes, abrir/cerrar forwards y rotar el token. Los assets estáticos
(`/`, `/app.js`, `/style.css`) no contienen secretos, pero todas las llamadas a
`/api/*` exigen `Authorization: Bearer`.

## Seguridad

- La API solo escucha en `wg0` (`10.0.0.1:8080`); nftables acepta `8080` por el
  túnel y descarta el resto.
- Token Bearer en `/etc/umbrel-tunnel/token` (`600`), rotable con
  `umbrel-tunnel token rotate` o desde la app.
- `wg0.conf`, claves y estado con permisos `600`/`700`.
- systemd endurecido: `NoNewPrivileges`, `ProtectSystem=strict`,
  `ProtectHome`, `RestrictNamespaces`, solo `CAP_NET_ADMIN`/`CAP_NET_RAW`,
  límites de memoria y tareas.
- El puerto público `22` está reservado para el SSH del VPS.
- Los servicios sensibles (RPC de Bitcoin, LND, Ollama, Portainer, SSH…) se
  marcan en la UI para que decidas con contexto.
- La app de Umbrel mantiene el login de Umbrel (`app_proxy`) **y** su propio
  login con `APP_PASSWORD` (cookie de sesión firmada, HttpOnly, SameSite,
  CSRF y límite de intentos).
- La configuración de WireGuard se genera desde campos estructurados. Se
  rechazan directivas arbitrarias como `PostUp`, `PostDown`, `PreUp`,
  `PreDown` o `SaveConfig`.
- El código `ut1` no transporta claves privadas. La URL de la API debe estar
  dentro de la subred del túnel para evitar peticiones a hosts arbitrarios.
- El contenedor del gateway necesita `NET_ADMIN` (crear `wg0` y escuchar en la
  IP del túnel) y `SYS_MODULE` + `/lib/modules:ro` para cargar el módulo
  WireGuard del host, igual que la app oficial de WireGuard. No monta el socket
  de Docker. Monta `${UMBREL_ROOT}/app-data` en solo lectura para detectar apps;
  es el privilegio de host más amplio del paquete y está documentado en
  [docs/SECURITY.md](docs/SECURITY.md).

## Red y puertos

| Elemento | Valor por defecto |
| --- | --- |
| Interfaz | `wg0` |
| Subred | `10.0.0.0/24` |
| VPS en el túnel | `10.0.0.1` |
| Umbrel en el túnel | `10.0.0.2` |
| Puerto WireGuard | `51820/udp` |
| API | `10.0.0.1:8080` |
| Puerto de la app en Umbrel | `8642` (interno `8081`) |
| Puertos internos de Umbrel | `20000–29999` |
| MTU | `1420` |

Rutas del VPS:

- `/etc/umbrel-tunnel/` — `config.json`, `token`, claves, `rules.nft`
- `/var/lib/umbrel-tunnel/` — `peers.json`, `forwards.json`
- `/etc/wireguard/wg0.conf`
- `/run/umbrel-tunnel/`

Rutas de la app:

- `${APP_DATA_DIR}/data/` — `config.json`, `session.key`, `wireguard/`,
  `haproxy.cfg`

Si usas `ufw` o `firewalld`, el instalador avisa: además de nftables necesitas
permitir el puerto WireGuard y el tráfico enrutado hacia `wg0`.

## Diagnóstico

```bash
sudo umbrel-tunnel doctor
systemctl status umbrel-tunnel umbrel-tunnel-firewall wg-quick@wg0
journalctl -u umbrel-tunnel -n 100 --no-pager
sudo wg show
sudo nft list table inet umbrel_tunnel
curl -fsS http://10.0.0.1:8080/health
```

En la app, la píldora **Túnel** indica si hay handshake; **VPS** y **Sync**
muestran el resultado de la última reconciliación.

Si el gateway no puede crear `wg0`, comprueba que el módulo del kernel esté
disponible en el host de Umbrel (`sudo modprobe wireguard`). El contenedor
necesita `NET_ADMIN` y, para cargar el módulo, `SYS_MODULE` con
`/lib/modules:ro`. No usa `/dev/net/tun`.

## Actualizar, backup y desinstalar

```bash
# Actualizar el binario desde una URL o ruta local
sudo umbrel-tunnel update --from https://…/umbrel-tunnel-linux-amd64 --sha256 <hex>

# Copia de seguridad (configuración, claves y estado)
sudo umbrel-tunnel backup --output /root/umbrel-tunnel-backup.tar.gz
sudo umbrel-tunnel restore --from /root/umbrel-tunnel-backup.tar.gz --force

# Desinstalar
sudo ./install.sh --uninstall          # conserva /etc/umbrel-tunnel y /var/lib/umbrel-tunnel
sudo ./install.sh --uninstall --purge  # borra también configuración y estado
```

## Desarrollo

```bash
# VPS
cd vps
gofmt -w .
go vet ./...
go test ./...
make dist          # binarios + tarballs + SHA256SUMS en vps/dist/
```

```bash
# App de Umbrel (gateway)
cd umbrel-tunnel/gateway
python3 -m pip install flask pyyaml waitress
python3 -m py_compile app.py catalog.py detect.py i18n.py proxy.py serve.py state.py sync.py vps.py wireguard.py
python3 -m unittest discover -s tests -v
```

Con Docker, se puede construir y probar la imagen del gateway:

```bash
cd umbrel-tunnel/gateway
docker build -t umbrel-tunnel-gateway:dev .
```

Para una ejecución local sin Umbrel:

```bash
UMBREL_TUNNEL_DEV=1 UMBREL_TUNNEL_DATA=/tmp/umbrel-tunnel-data \
  UMBREL_APP_DATA=/tmp/umbrel-app-data PORT=8081 python3 serve.py
```

La contraseña de desarrollo es `dev`. No uses `UMBREL_TUNNEL_DEV` en producción.

Variables de entorno útiles en el gateway:

| Variable | Por defecto | Uso |
| --- | --- | --- |
| `APP_PASSWORD` | — | contraseña de login; Umbrel la inyecta |
| `APP_VERSION` | `1.0.0` | versión mostrada |
| `UMBREL_TUNNEL_DATA` | `/data` | estado, claves y configuración |
| `UMBREL_APP_DATA` | `/umbrel-app-data` | manifiestos de apps (solo lectura) |
| `NETWORK_IP` | `10.21.0.0` | red de Umbrel para detectar solapes |
| `UMBREL_TUNNEL_HOST_SERVICES` | `1` | detectar SSH/panel del host |
| `UMBREL_TUNNEL_WG_CONF` | `/etc/wireguard/wg0.conf` | ruta de `wg0.conf` (tests) |
| `UMBREL_TUNNEL_HAPROXY_CONF` | `/etc/haproxy/haproxy.cfg` | ruta de HAProxy (tests) |
| `UMBREL_TUNNEL_HAPROXY_PID` | `/var/run/haproxy.pid` | PID de HAProxy (tests) |
| `UMBREL_TUNNEL_INSTALL_URL` | `…/AlbercoinDev/umbrel-tunnel/main/vps/install.sh` | script que muestra el asistente |
| `UMBREL_TUNNEL_BINARY_BASE` | `…/releases/latest/download` | base del binario del VPS |
| `UMBREL_TUNNEL_DEV` | — | `1` permite arrancar sin `APP_PASSWORD` |

Documentación adicional:

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- [docs/SECURITY.md](docs/SECURITY.md)
- [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)
- [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)

## Limitaciones actuales

- El proxy local de Umbrel solo gestiona **TCP**. Para UDP usa
  `umbrel-tunnel forward add --protocol udp` en el VPS.
- La app no se ha probado en un Umbrel real en este entorno de desarrollo (no
  hay Docker ni HAProxy locales). El gateway tiene tests unitarios; el código Go
  tiene tests unitarios y de integración. Las pruebas reales en umbrelOS las
  hace el usuario.
- El nombre de la red compartida se asume `umbrel_main_network`; Umbrel lo
  inyecta en tiempo de ejecución.

## Estructura

```
umbrel-tunnel/
  umbrel-app.yml              manifiesto de la app
  docker-compose.yml          app_proxy + gateway
  data/.gitkeep               datos persistentes
  gateway/                    Flask, detección, HAProxy, WireGuard, sync
    i18n/                     catálogos es.json / en.json
    tests/                    tests unitarios del gateway
vps/
  cmd/umbrel-tunnel/          CLI y servidor
  internal/                   config, state, wireguard, firewall, pair, service, httpapi…
  packaging/                  unidades systemd, tmpfiles, sysctl
  install.sh                  instalador de una línea
  scripts/push.sh             build + despliegue por SSH
  Makefile                    cross-compile y release
docs/                         arquitectura, seguridad, desarrollo, diagnóstico
```

## Licencia

MIT. Consulta [LICENSE](LICENSE).
