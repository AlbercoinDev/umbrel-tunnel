# umbrel-tunnel

Expón servicios de tu Umbrel a través de un VPS con IP fija usando un túnel
WireGuard. La app de Umbrel detecta las aplicaciones instaladas y los servicios
de UmbrelOS, y abre o cierra sus puertos públicos en el VPS desde una interfaz
web. La API del VPS solo escucha dentro del túnel y está protegida con un token.

```
Internet ──► VPS (IP fija) ──► wg0 ──► Umbrel ──► app/contenedor
             DNAT :8333       túnel     HAProxy   10.0.0.x:8333
             nftables         10.0.0.1  10.0.0.2
```

- **VPS**: un único binario Go estático + systemd, WireGuard en el kernel y
  nftables. Sin Docker ni Python. Pensado para 128–256 MB de RAM.
- **Umbrel**: app con gateway en Flask, `docker-socket-proxy` para detectar
  contenedores, HAProxy para el proxy TCP local y `wg-quick` para el túnel.
- **Sin DDNS ni QR**: el VPS tiene IP fija y el emparejamiento es un código
  `ut1.…` que se pega en la app.

## Requisitos

**VPS**

- Debian 12/13 o Ubuntu 22.04/24.04+ (`amd64` o `arm64`).
- Acceso root (o `sudo`).
- IP pública fija y salida a Internet.
- Puertos: el que elijas para WireGuard (por defecto `51820/udp`) y los puertos
  públicos que quieras exponer. El `22/tcp` del VPS queda reservado para SSH.

**Umbrel**

- UmbrelOS con Docker.
- La app se instala como cualquier app de Umbrel (carpeta `umbrel-tunnel/`).

## Instalación del VPS

### Opción A: desde este repositorio (recomendada mientras no haya GitHub)

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

### Opción B: tarball manual

```bash
cd vps
make dist
scp dist/umbrel-tunnel-1.0.0-linux-amd64.tar.gz root@203.0.113.10:/tmp/
ssh root@203.0.113.10
tar -xzf /tmp/umbrel-tunnel-1.0.0-linux-amd64.tar.gz -C /tmp
cd /tmp/umbrel-tunnel-1.0.0-linux-amd64
sudo ./install.sh --endpoint 203.0.113.10
```

### Opción C: una línea (cuando el proyecto esté en GitHub)

```bash
curl -fsSL https://raw.githubusercontent.com/<OWNER>/<REPO>/main/vps/install.sh \
  | sudo bash -s -- --binary https://github.com/<OWNER>/<REPO>/releases/latest/download/umbrel-tunnel-linux-amd64
```

### Qué hace el instalador

1. Comprueba sistema, arquitectura, systemd, Internet, RAM/disco y puertos.
2. Instala solo lo que falta (`wireguard`, `wireguard-tools`, `nftables`, etc.).
3. Copia el binario a `/usr/local/bin/umbrel-tunnel`.
4. Instala las unidades `wg-quick@wg0`, `umbrel-tunnel-firewall` y `umbrel-tunnel`.
5. Crea claves, token, configuración y el peer de Umbrel.
6. Verifica que la API responde en `10.0.0.1:8080` y que escucha solo en el túnel.
7. Imprime el código de emparejamiento y lo guarda en
   `/root/umbrel-tunnel-pairing.txt` (permisos `600`).

Opciones principales:

```text
--endpoint IP        IP pública fija (si se omite, se detecta)
--wg-port PORT       puerto UDP de WireGuard (51820)
--api-port PORT      puerto de la API dentro del túnel (8080)
--subnet CIDR        subred del túnel (10.0.0.0/24)
--umbrel-pubkey KEY  emparejamiento manual
--public-api         expone la API fuera del túnel (no recomendado)
--binary URL|RUTA    binario a instalar
--force              sustituye configuración existente (hace backup de wg0.conf)
--no-start           instala sin arrancar
--dry-run            muestra lo que haría
--uninstall [--purge] desinstala (y borra configuración con --purge)
```

Reejecutar el instalador es seguro: conserva la configuración y las claves
existentes salvo que uses `--force`.

## Emparejar Umbrel

1. Instala la app `umbrel-tunnel` en Umbrel.
2. En el VPS ejecuta `umbrel-tunnel pair` (o usa el código que imprimió el
   instalador).
3. Abre la app, pestaña **Conexión**, pega el código `ut1.…` y pulsa
   **Emparejar**.

El código incluye la URL de la API (`http://10.0.0.1:8080`), el token, la
configuración de WireGuard del cliente, el endpoint del VPS y la IP del túnel.

### Emparejamiento manual

Si prefieres no usar el código, o quieres regenerar claves:

```bash
# En el VPS, sin clave de Umbrel:
umbrel-tunnel init --endpoint 203.0.113.10 --umbrel-pubkey "<CLAVE_PUBLICA_UMBREL>"

# O añade un peer después:
umbrel-tunnel peer add --name umbrel --ip 10.0.0.2 --pubkey "<CLAVE_PUBLICA_UMBREL>"
```

En la app, pestaña **Conexión → Emparejamiento manual**: introduce endpoint y
clave pública del servidor (`umbrel-tunnel pair -json` los muestra), genera la clave
del cliente y añade al VPS la clave pública que imprime la app. También puedes
pegar una configuración `[Interface]/[Peer]` completa y aplicarla.

## Uso

- **Servicios**: lista detectada de apps y servicios de UmbrelOS. Elige el
  puerto público y pulsa **Abrir**. El VPS crea el DNAT y la app configura
  HAProxy en el lado de Umbrel.
- **Puertos abiertos**: estado de cada exposición, activar/desactivar, cambiar
  el puerto público o cerrarlo.
- **Conexión**: estado del túnel y del handshake, configuración de WireGuard y
  emparejamiento manual.
- **Avanzado**: URL/token de la API, intervalo de sincronización y notas.

Los servicios del sistema (SSH, panel de UmbrelOS) se marcan como **sistema** y
**sensible**. El puerto público `22` está bloqueado para no pisar el SSH del
VPS; para SSH de Umbrel se propone `2222`.

La sincronización es declarativa: la app compara lo que quieres exponer con los
forwards del VPS y crea, actualiza o elimina lo necesario. Se ejecuta al cambiar
algo y cada `sync_interval` segundos (30 por defecto).

## CLI del VPS

```bash
umbrel-tunnel serve                      # API (lo arranca systemd)
umbrel-tunnel init [opciones]            # configuración, claves, token y peer
umbrel-tunnel pair [--json] [--new] [--rotate-token]
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
| DELETE | `/api/peers/{id}` | Elimina peer |
| GET | `/api/peers/{id}/config` | Configuración WireGuard del peer |
| GET/POST | `/api/forwards` | Lista/crea forwards |
| PATCH/DELETE | `/api/forwards/{id}` | Actualiza/elimina forward |
| POST | `/api/token/rotate` | Rota el token |

Un forward usa `public_port` (el antiguo `dport` se migra al leer el estado):

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

## Red y puertos

| Elemento | Valor por defecto |
| --- | --- |
| Interfaz | `wg0` |
| Subred | `10.0.0.0/24` |
| VPS en el túnel | `10.0.0.1` |
| Umbrel en el túnel | `10.0.0.2` |
| Puerto WireGuard | `51820/udp` |
| API | `10.0.0.1:8080` |
| Puertos internos de Umbrel | `20000–29999` |
| MTU | `1420` |

Rutas:

- `/etc/umbrel-tunnel/` — `config.json`, `token`, claves, `rules.nft`
- `/var/lib/umbrel-tunnel/` — `peers.json`, `forwards.json`
- `/etc/wireguard/wg0.conf`
- `/run/umbrel-tunnel/`

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
disponible en el host de Umbrel (`sudo modprobe wireguard`). El contenedor solo
necesita `NET_ADMIN`; no usa `/dev/net/tun` ni carga módulos.

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
export PATH=/tmp/opencode/go/bin:$PATH   # o tu instalación de Go
gofmt -w .
go vet ./...
go test ./...
make dist          # binarios + tarballs + SHA256SUMS en vps/dist/
```

```bash
# App de Umbrel
cd umbrel-tunnel
python3 -m py_compile gateway/*.py
# Sin Docker local no se puede probar el runtime completo; requiere Umbrel real.
```

Variables de entorno útiles en el gateway:

| Variable | Por defecto | Uso |
| --- | --- | --- |
| `DOCKER_HOST` | `tcp://socket-proxy:2375` | API de Docker |
| `UMBREL_APP_DATA` | `/umbrel-app-data` | manifests/exports de apps |
| `UMBREL_NETWORK` | `umbrel_main_network` | red compartida de Umbrel |
| `UMBREL_TUNNEL_HOST_SERVICES` | `1` | detectar SSH/panel del host |
| `APP_VERSION` | `1.0.0` | versión mostrada |

## Limitaciones actuales

- El proxy local de Umbrel solo gestiona **TCP**. Para UDP usa
  `umbrel-tunnel forward add --protocol udp` en el VPS.
- La app no se ha probado en un Umbrel real en este entorno (no hay Docker ni
  HAProxy locales). El código Go sí tiene tests unitarios y de integración.
- El nombre de la red compartida se asume `umbrel_main_network`; si tu Umbrel
  usa otro, define `UMBREL_NETWORK` en el compose.
- El alojamiento en GitHub y las URLs del manifiesto son marcadores
  (`umbrel-tunnel/umbrel-tunnel`) hasta que se publique el repositorio.

## Estructura

```
vps/
  cmd/umbrel-tunnel/    CLI y servidor
  internal/             config, state, wireguard, firewall, pair, service, httpapi…
  packaging/            unidades systemd, tmpfiles, sysctl
  install.sh            instalador de una línea
  scripts/push.sh       build + despliegue por SSH
  Makefile              cross-compile y release
umbrel-tunnel/
  gateway/              Flask, detección Docker, HAProxy, WireGuard, sync
  docker-compose.yml    app_proxy, socket-proxy y gateway
  umbrel-app.yml        manifiesto de Umbrel
```
