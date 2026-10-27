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
   TCP local, relay UDP con sesiones y `wg-quick` para el túnel.
- **Sin DDNS ni QR**: el VPS tiene IP fija y el emparejamiento es un código
  `ut1.…` que se pega en la app.
- **Bilingüe**: interfaz en español por defecto e inglés opcional. En la
  primera visita se detecta el idioma del navegador/UmbrelOS.
- **HTTPS y TLS opcionales**: dominios web compartiendo 443 y terminación TLS
  TCP (por ejemplo Electrs 50002 → 50001), con certificados de Let's Encrypt y
  renovación automática. Configurables también después de vincular el VPS.

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
2. Abre la app. Si aún no hay VPS vinculado, **Configuración y diagnóstico** muestra el
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
scp dist/umbrel-tunnel-1.0.1-linux-amd64.tar.gz root@203.0.113.10:/tmp/
ssh root@203.0.113.10
tar -xzf /tmp/umbrel-tunnel-1.0.1-linux-amd64.tar.gz -C /tmp
cd /tmp/umbrel-tunnel-1.0.1-linux-amd64
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
2. Abre la app y ve a **Configuración y diagnóstico**. Introduce la IP pública del VPS y pulsa
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

En la app, **Configuración y diagnóstico → Emparejamiento manual**: introduce endpoint,
clave pública del servidor, IP de Umbrel, subred y MTU. La app genera la clave
local, aplica la configuración y muestra la clave pública que debe registrarse
en el VPS. Si la app ya está emparejada por API/token, el registro es
automático.

## Uso

- **Servicios y puertos**: servicios detectados y manuales en una sola lista,
  con búsqueda, filtro por tipo de puerto y opción de ocultar los internos.
  Cada puerto muestra qué es (Web/HTTP, RPC, P2P, ZMQ, Electrum, Lightning,
  métricas, base de datos o TCP/UDP) y si es **sensible** o **interno**.
  Permite publicar TCP/UDP, pausar, reanudar, cambiar el puerto o dejar de
  publicar sin borrar el servicio.
- **Servicios web**: se publican por subdominio en el puerto 80 (HTTP) o 443
  (HTTPS). El puerto interno de la app no se usa como puerto público: el VPS
  enruta por `Host` y el proxy local conecta con el puerto real del contenedor.
  Solo los servicios que no son web (TCP/UDP/TLS) tienen puerto público
  personalizable.
- **Añadir servicio manual**: guarda un servicio o lo publica directamente.
  TCP + UDP crea dos reglas independientes y muestra el resultado de cada una.
- **Configuración y diagnóstico**: botón separado para conexión, diagnóstico,
  WireGuard y ajustes avanzados plegados. Las ayudas se pueden abrir con
  teclado, ratón o toque. El asistente se muestra automáticamente la primera vez.

El VPS crea el DNAT y Umbrel configura HAProxy para TCP o el relay para UDP.
Una regla aplicada no demuestra que el servicio responda desde Internet.
Consulta [la gestión de publicaciones](docs/PUBLICATIONS.md) y
[dominios, HTTPS y TLS TCP con renovación automática](docs/TLS.md).

Los servicios del sistema (SSH, panel de UmbrelOS por HTTP/HTTPS) se marcan como
**sistema** y **sensible**. El puerto público `22` está bloqueado para no pisar
el SSH del VPS; para SSH de Umbrel se propone `2222`.

La sincronización es declarativa: la app compara lo que quieres exponer con los
forwards del VPS y crea, actualiza o elimina lo necesario. Se ejecuta al cambiar
algo y cada `sync_interval` segundos (30 por defecto). Cada exposición muestra su
estado real: si el VPS rechaza el puerto o HAProxy no arranca, la fila queda en
error con el detalle y un botón **Reintentar**, en vez de un falso
"sincronizado".

### Servicios manuales

En **Servicios y puertos → Añadir servicio manual** puedes exponer un contenedor que la
detección automática no reconoce. Indica nombre (opcional), host o contenedor,
puerto, protocolo y, si quieres, un puerto público concreto:

- **Añadir y abrir** crea el servicio y abre el puerto en el VPS en un solo paso.
- **Solo añadir** guarda el servicio sin abrirlo; luego puedes pulsar **Abrir**
  en su fila.

Si el puerto público solicitado ya está ocupado en el VPS, la app reintenta una
vez en un puerto libre y te avisa del cambio. Los errores se muestran como
notificaciones persistentes con el detalle del VPS o de HAProxy, y cada fila
ofrece **Reintentar** y **Cerrar**. El panel **Diagnóstico** comprueba túnel,
API del VPS, peer, forwards y HAProxy sin abrir ni cerrar puertos.

El puerto público manual se rellena con el puerto del servicio. Puedes editarlo;
una vez editado, no se sobrescribe al cambiar el puerto del servicio.

### Detección de servicios

La app **no monta el socket de Docker**. Lee, en modo solo lectura:

- `${UMBREL_ROOT}/app-data/<app-id>/umbrel-app.yml`
- `${UMBREL_ROOT}/app-data/<app-id>/docker-compose.yml`
- `${UMBREL_ROOT}/app-data/<app-id>/app-gateway.json` (destino resuelto por umbreld)
- `${UMBREL_ROOT}/app-data/<app-id>/exports.sh` (solo se analiza con regex; nunca se ejecuta)
- `${UMBREL_ROOT}/app-data/<app-id>/.env` y `.env.app_proxy` (también solo como texto)

La detección interpreta el compose de forma estática, sin ejecutar nada:

- **Puertos publicados** (`ports`) y **puertos internos** (`expose`). Se aceptan
  las formas corta y larga, `host:container`, solo `container`, con o sin
  `/tcp`/`/udp`, IP de host, IPv6 y rangos (`8000-8010`) hasta 256 puertos.
  También se conservan los puertos sin comillas (`10025:25`), que YAML podría
  confundir con un número en base 60.
- **Red del host** (`network_mode: host`): esos servicios no publican puertos;
  se detectan contra la puerta de enlace de la red Docker, igual que SSH y el
  panel de UmbrelOS.
- **Espacios de red compartidos** (`network_mode: service:…` y
  `container:…`): el destino es el contenedor que posee la red, no el servicio
  que la comparte.
- **Interpolación de variables** de Docker Compose (`$VAR`, `${VAR}`,
  `${VAR:-def}`, `${VAR-default}`, `${VAR:+alt}`, `${VAR+alt}`, `${VAR:?err}` y
  `$$`), usando los valores estáticos de `exports.sh`, `.env` y del propio
  compose. `.env.app_proxy` puede sobrescribir `APP_HOST`/`APP_PORT`, como hace
  umbreld. Así se resuelven, por ejemplo, los puertos de Bitcoin (`8332`,
  `8333`) y Electrs (`50001`), que en origen son `${APP_BITCOIN_RPC_PORT}` y
  similares.
- **Inferencia desde el entorno y el comando**: direcciones de escucha
  (`0.0.0.0:3000`, `[::]:8082`), variables `BIND`/`LISTEN`/`ADDR*` y flags de
  servidor (`--port`, `--bind`, `--rpcbind`, `-zmqpub*`). Las variables
  compartidas por todas las apps de un proyecto, los puertos de cliente
  (`*_HOST`/`*_URL` apuntando a otro contenedor) y los umbrales numéricos no se
  atribuyen al servicio equivocado.
- **Escaneo activo (en segundo plano)**: la app resuelve el nombre DNS de cada
  contenedor y prueba conexiones TCP solo contra direcciones privadas de la red
  Docker. Los puertos abiertos se prueban con una petición HTTP y se cachean
  durante `UMBREL_TUNNEL_SCAN_TTL` segundos (300 por defecto). Nunca escanea
  apps con `network_mode: host`, así que no toca el host de Umbrel. Se puede
  desactivar con `UMBREL_TUNNEL_SCAN=0`. Los puertos declarados en el compose
  siguen apareciendo aunque el contenedor esté parado; el escaneo solo añade
  los que la imagen abre por su cuenta.

Cada puerto detectado recibe un **tipo** y una **confianza** a partir de la
evidencia disponible (proxy web, puerto declarado, sonda HTTP, Prometheus,
nombre del servicio, ZMQ/RPC/P2P/Electrum/Lightning…). Los puertos de base de
datos y métricas se marcan como **internos** para poder ocultarlos.

Usa los nombres DNS de Docker (`<app-id>_<servicio>_1`) como destino, de modo
que el proxy sigue funcionando aunque cambie la IP del contenedor. Los servicios
detectados muestran debajo la IP resuelta, solo como información. Las IPs de
`app-gateway.json` se asocian al contenedor declarado en el compose cuando es
posible. Si una app no se detecta, añade un servicio manual en
**Servicios y puertos**.

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
umbrel-tunnel forward list --json
umbrel-tunnel forward show <id>
umbrel-tunnel forward check <id>
umbrel-tunnel forward add --name web --public-port 8080 --target-ip 10.0.0.2 \
  --target-port 20000 [--protocol tcp|udp] [--disabled]
umbrel-tunnel forward rm <id>
umbrel-tunnel forward enable|disable <id>
umbrel-tunnel forward edit <id> --public-port 9001
umbrel-tunnel forward reconcile
umbrel-tunnel status
umbrel-tunnel token show|rotate
umbrel-tunnel doctor [--json]
umbrel-tunnel update [--from URL|PATH] [--sha256 HEX] [--no-restart] [--no-units]
umbrel-tunnel backup [--output FILE]
umbrel-tunnel restore --from FILE [--force]
umbrel-tunnel uninstall [--purge]
umbrel-tunnel version
```

La CLI y la app permiten gestionar TCP y UDP. Los comandos de publicaciones y
las mutaciones de peers usan la API local autenticada del daemon para evitar
que un proceso independiente sobrescriba su estado. Requieren el servicio activo.
Los cambios externos sobre publicaciones de Umbrel se detectan como conflictos:
la app ofrece adoptarlos o restaurar su configuración, sin sobrescribirlos a ciegas.

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
  `ProtectHome`, `RestrictNamespaces`, solo `CAP_NET_ADMIN`/`CAP_NET_RAW`/
  `CAP_NET_BIND_SERVICE` (listeners HTTPS/TLS),
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
# Primera subida a 1.3.2 o posterior desde una instalación anterior: su
# `update` todavía no resuelve la release sola (`error: falta --from`), así
# que pasa la URL una vez.
sudo umbrel-tunnel update \
  --from "https://github.com/AlbercoinDev/umbrel-tunnel/releases/latest/download/umbrel-tunnel-linux-$(dpkg --print-architecture)"

# Desde 1.3.2 en adelante: resuelve la última release para la arquitectura del
# VPS, verifica el .sha256, comprueba que el binario nuevo se ejecuta, actualiza
# las unidades systemd y reinicia el servicio. Configuración, claves y peers no
# se tocan.
sudo umbrel-tunnel update

# Variantes explícitas (versión concreta, binario local o checksum a mano)
sudo umbrel-tunnel update \
  --from https://github.com/AlbercoinDev/umbrel-tunnel/releases/download/v1.3.2/umbrel-tunnel-linux-amd64
sudo umbrel-tunnel update --from ./umbrel-tunnel-linux-amd64 --sha256 <hex>

# Copia de seguridad (configuración, claves y estado)
sudo umbrel-tunnel backup --output /root/umbrel-tunnel-backup.tar.gz
sudo umbrel-tunnel restore --from /root/umbrel-tunnel-backup.tar.gz --force

# Desinstalar
sudo ./install.sh --uninstall          # conserva /etc/umbrel-tunnel y /var/lib/umbrel-tunnel
sudo ./install.sh --uninstall --purge  # borra también configuración y estado
```

`update` sustituye `/usr/local/bin/umbrel-tunnel` y refresca las unidades systemd
que van embebidas en el binario. Si una versión cambia `sysctl`, `tmpfiles` o el
propio `install.sh`, reinstala con el instalador (es idempotente y conserva la
configuración):

```bash
curl -fsSL https://raw.githubusercontent.com/AlbercoinDev/umbrel-tunnel/main/vps/install.sh \
  | sudo bash -s -- --endpoint <IP> \
      --binary-base https://github.com/AlbercoinDev/umbrel-tunnel/releases/latest/download
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
| `APP_VERSION` | `1.4.0` | versión mostrada |
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

- El relay UDP admite respuestas con sesiones independientes, límite global de
  512 sesiones y caducidad de 60 segundos de inactividad. No es un proxy transparente:
  el servicio de destino no recibe la IP original del cliente.
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
    units/files/              unidades systemd, tmpfiles, sysctl (embebidas en el binario)
  install.sh                  instalador de una línea
  scripts/push.sh             build + despliegue por SSH
  Makefile                    cross-compile y release
docs/                         arquitectura, seguridad, desarrollo, diagnóstico
```

## Licencia

MIT. Consulta [LICENSE](LICENSE).
