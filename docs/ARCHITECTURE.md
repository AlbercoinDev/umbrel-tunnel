# Arquitectura

`umbrel-tunnel` tiene dos mitades que se comunican por un túnel WireGuard:

1. **VPS**: binario Go + systemd. Es el único con IP pública fija. Abre los
   puertos públicos con DNAT y ejecuta una API mínima que solo escucha dentro
   del túnel.
2. **App de Umbrel**: contenedor con Flask/waitress, HAProxy y `wg-quick`.
   Detecta los servicios locales, decide qué exponer y reconcilia el estado con
   la API del VPS.

```
                       VPS (Debian/Ubuntu)
                 ┌─────────────────────────────┐
 Internet ──────►│ nftables DNAT :8333         │
                 │        │                    │
                 │        ▼                    │
                 │   wg0 10.0.0.1 ───────────┐ │
                 │   API 10.0.0.1:8080       │ │
                 │   systemd umbrel-tunnel   │ │
                 └───────────────────────────┼─┘
                                             │ WireGuard
                 ┌───────────────────────────┼─┐
                 │ Umbrel   wg0 10.0.0.2     │ │
                 │   HAProxy :20000 ◄────────┘ │
                 │     │                       │
                 │     ▼                       │
                 │   app_web_1:3000            │
                 │   gateway 8081 (app_proxy)  │
                 └─────────────────────────────┘
```

## Componentes

### VPS (`vps/`)

- `cmd/umbrel-tunnel`: CLI y servidor HTTP.
- `internal/config`: rutas, configuración, token y validación.
- `internal/state`: peers y forwards en JSON atómico.
- `internal/wireguard`: claves, `wg0.conf` y recarga con `wg syncconf`.
- `internal/firewall`: reglas nftables (DNAT, forward, aislamiento).
- `internal/service`: orquestación de `init`, `serve`, `pair`, backups.
- `internal/httpapi`: API Bearer y panel web estático.
- `internal/pair`: códec `ut1`.
- `install.sh`: instalación idempotente de una línea.

La API escucha por defecto en `10.0.0.1:8080`. El firewall solo acepta ese
puerto por `wg0`; `--public-api` es una excepción explícita y no recomendada.

### Gateway de Umbrel (`umbrel-tunnel/gateway/`)

- `app.py`: rutas HTTP, login, CSRF, API interna, emparejamiento y sincronización.
- `detect.py`: detección de apps y servicios del host sin socket de Docker.
- `scan.py`: escaneo TCP en segundo plano y sonda HTTP/TLS con caché por host.
- `catalog.py`: nombres, descripciones y marcas de sensibilidad de servicios
  conocidos, y valores por defecto para interpolar el compose. No añade puertos
  por sí mismo.
- `proxy.py`: renderizado, validación y recarga de HAProxy.
- `udp.py`: relay de datagramas con sesiones independientes, límites y caducidad.
- `wireguard.py`: generación/validación estricta de `wg0.conf`, claves y estado.
- `sync.py`: reconciliación declarativa de exposiciones y forwards.
- `vps.py`: cliente HTTP de la API del VPS.
- `state.py`: estado persistente y secreto de sesión.
- `i18n.py` + `i18n/*.json`: catálogos español/inglés.
- `serve.py`: entrada de producción con waitress.
- `templates/`, `static/`: UI bilingüe y login.

## Flujo de emparejamiento

```
Umbrel (app)                              VPS
 │ POST /api/bootstrap                     │
 │ genera clave + token, guarda bootstrap  │
 │ muestra comando de instalación          │
 │ ─── el usuario ejecuta install.sh ────► │
 │                                         │ instala, crea config/keys
 │                                         │ pre-registra pubkey de Umbrel
 │ ◄────────── bloque ut1 ──────────────── │
 │ valida que coincide con el bootstrap    │
 │ escribe wg0.conf y wg-quick up          │
 │ ──── POST/PUT /api/peers ─────────────► │ (idempotente)
 │ sync de forwards                        │
```

El código `ut1` **no contiene claves privadas**. El VPS solo guarda la clave
pública de Umbrel. La app valida el token, el endpoint, la URL de la API, la
subred, la IP y el MTU del código contra el bootstrap pendiente; así un código
de otro VPS no puede redirigir el túnel. Si se rota la clave local, la app llama
a `PUT /api/peers/{id}` y el VPS recarga WireGuard; si la recarga falla, el VPS
revierte la clave anterior.

## Flujo de una exposición

1. La app detecta un servicio (`target_ip`, `target_port`, protocolo, tipo).
2. El usuario elige el puerto público. Si el servicio es web (`kind = http`) se
   publica por subdominio en el puerto 80 (HTTP) o 443 (HTTPS) y el puerto
   interno no se usa como público. Para el resto (TCP/UDP/TLS) elige un puerto
   personalizable y la app asigna un puerto interno del túnel (`20000–29999`).
3. `sync.py` pide al VPS un forward `public_port → 10.0.0.2:tunnel_port` con el
   modo de acceso (`direct`, `http`, `https` o `tls`) y el dominio.
4. El VPS crea la regla nftables DNAT y la aplica.
5. La app configura HAProxy (TCP) o el relay (UDP) escuchando en
   `10.0.0.2:tunnel_port` y reenvía al contenedor por su nombre DNS de Docker.
6. Al desactivar o cerrar, se elimina el forward del VPS y HAProxy se
   reconfigura. Los forwards con prefijo `umbrel:` que ya no corresponden a
   ninguna exposición se limpian de forma conservadora.

En los modos web, el VPS recibe la petición en 80/443, elige el forward por la
cabecera `Host` del dominio y la envía a `10.0.0.2:<tunnel_port>`; HAProxy
termina la última conexión contra el puerto real del contenedor. Varias
publicaciones HTTPS comparten el 443 y se distinguen por dominio. El puerto
público de una exposición `http`/`https` es fijo: editarlo devuelve
`error.web_port_fixed`.

Las reglas nuevas incluyen propiedad explícita `managed_by`; las independientes
del VPS se conservan. Una copia de los valores remotos aplicados permite detectar
cambios externos antes de sobrescribirlos. La CLI de publicaciones usa el daemon
como propietario único del estado. Véase [Publicaciones](PUBLICATIONS.md) para
los límites UDP, resolución de conflictos y preparación futura para dominios/TLS.

La sincronización es idempotente: compara el estado remoto con el deseado y
crea, actualiza o elimina solo lo necesario. Se ejecuta al cambiar algo y cada
`sync_interval` segundos.

## Detección sin socket de Docker

Umbrel instala cada app en `${UMBREL_ROOT}/app-data/<app-id>`. El gateway monta
ese árbol en solo lectura y lee:

- `umbrel-app.yml`: nombre y puerto público de la app.
- `docker-compose.yml`: servicios, `ports`, `expose`, `container_name`,
  `network_mode` y `app_proxy`.
- `app-gateway.json`: destino resuelto por umbreld (`APP_HOST`, `APP_PORT`).
- `exports.sh`, `.env` y `.env.app_proxy`: solo asignaciones y
  `export KEY=value` estáticos, con regex. **Nunca se ejecutan.** `.env.app_proxy`
  sobrescribe `APP_HOST`/`APP_PORT`, igual que en umbreld.

El compose se interpreta de forma estática:

- `ports` admite formato corto y largo, solo contenedor o `host:container`, IP
  de host/IPv6, `/tcp` y `/udp`, y rangos (hasta `MAX_RANGE_PORTS = 256`). Los
  escalares sin comillas se cargan con un loader que evita la interpretación
  YAML de base 60 (`10025:25` no se convierte en `601525`).
- `expose` aporta puertos internos (TCP por defecto; se respeta `/udp`).
- Las variables de Compose (`$VAR`, `${VAR}`, `${VAR:-def}`, `${VAR-default}`,
  `${VAR:+alt}`, `${VAR+alt}`, `${VAR:?err}`, `$$`) se expanden con los valores
  de `exports.sh`, `.env` y del propio compose. Sin esto se perderían puertos
  como Bitcoin `8332/8333` y Electrs `50001`, declarados como `${...}`.
- Los servicios con `network_mode: host` no publican puertos: se apuntan a la
  puerta de enlace de la red Docker, igual que SSH y el panel HTTP/HTTPS.
- Con `network_mode: service:…` o `container:…` se usa el contenedor que posee
  el espacio de red compartido.

La detección combina tres capas:

1. **Declarativa.** El destino web preferido es el contenedor de `app_proxy`
   (el puerto real tras el proxy de UmbrelOS). Los puertos de `ports`/`expose`
   y los del manifiesto se ofrecen como endpoints de protocolo.
2. **Inferencia desde el entorno y el comando.** Se aceptan direcciones de
   escucha (`0.0.0.0:3000`, `[::]:8082`), variables `BIND`/`LISTEN`/`ADDR*` y
   flags de servidor (`--port`, `--bind`, `--rpcbind`, `-zmqpub*`). Las
   variables compartidas por todo el proyecto (`LISTEN_HTTP_PORT` de un ancla
   YAML), los puertos de cliente (`*_HOST`/`*_URL` que apuntan a otro
   contenedor), los umbrales numéricos y los sidecars que no escuchan
   (`worker`, `migrate`, `setup`…) se descartan. Un puerto ya declarado por otro
   servicio de la misma app no se vuelve a atribuir por entorno.
3. **Escaneo activo.** `scan.py` resuelve el nombre DNS de cada contenedor y
   prueba conexiones TCP solo contra direcciones privadas de la red Docker. Los
   puertos abiertos se prueban con una petición HTTP y se cachean durante
   `UMBREL_TUNNEL_SCAN_TTL` segundos (300 por defecto). Nunca escanea apps con
   `network_mode: host`, así que no toca el host de Umbrel. Se puede desactivar
   con `UMBREL_TUNNEL_SCAN=0`; `UMBREL_TUNNEL_SCAN_FULL=1` amplía el rango de
   1–10000 al rango completo. Los puertos declarados siguen apareciendo aunque
   el contenedor esté parado. **Refrescar servicios** invalida la caché y
   relanza el escaneo en segundo plano; la UI recoge el resultado en el
   siguiente sondeo.

Cada puerto recibe un **tipo** (`http`, `rpc`, `p2p`, `zmq`, `electrum`,
`lightning`, `metrics`, `database`, `tcp`, `udp`) y una **confianza**
(`high`/`medium`/`low`) a partir de la evidencia: proxy web, puerto declarado,
sonda HTTP/Prometheus, nombre del servicio, flags RPC/P2P/ZMQ o el propio
puerto. Los tipos `database` y `metrics` se marcan como **internos** para poder
ocultarlos en la UI. El catálogo ya no aporta puertos: solo nombres,
descripciones, marcas de sensibilidad y valores por defecto para interpolar el
compose. Si una app no se detecta, el usuario puede añadir un servicio manual.

Nunca se devuelven variables de entorno ni rutas de datos de otras apps por la
API.

## Idioma

El orden de resolución es:

1. `?lang=es|en`
2. cookie `ut_lang`
3. `Accept-Language` del navegador
4. `UMBREL_LANG` / `LANG` / `LC_ALL`
5. español

La UI muestra un selector ES/EN en la cabecera y en el login. Los catálogos
tienen exactamente las mismas claves y un test lo verifica.

## Persistencia

- Gateway: `${APP_DATA_DIR}/data/` (`config.json`, `session.key`,
  `wireguard/`, `haproxy.cfg`).
- VPS: `/etc/umbrel-tunnel/` (configuración, token, claves) y
  `/var/lib/umbrel-tunnel/` (peers, forwards).

Los secretos se escriben con permisos `600` y se reemplazan de forma atómica.
