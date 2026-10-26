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
- `catalog.py`: nombres, puertos y marcas de sensibilidad conocidos.
- `proxy.py`: renderizado, validación y recarga de HAProxy.
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

1. La app detecta un servicio (`target_ip`, `target_port`, protocolo).
2. El usuario elige un puerto público. La app asigna un puerto interno del
   túnel (`20000–29999`) y guarda la exposición.
3. `sync.py` pide al VPS un forward `public_port → 10.0.0.2:tunnel_port`.
4. El VPS crea la regla nftables DNAT y la aplica.
5. La app renderiza HAProxy escuchando en `10.0.0.2:tunnel_port` y reenvía al
   contenedor de la app por su nombre DNS de Docker.
6. Al desactivar o cerrar, se elimina el forward del VPS y HAProxy se
   reconfigura. Los forwards con prefijo `umbrel:` que ya no corresponden a
   ninguna exposición se limpian de forma conservadora.

La sincronización es idempotente: compara el estado remoto con el deseado y
crea, actualiza o elimina solo lo necesario. Se ejecuta al cambiar algo y cada
`sync_interval` segundos.

## Detección sin socket de Docker

Umbrel instala cada app en `${UMBREL_ROOT}/app-data/<app-id>`. El gateway monta
ese árbol en solo lectura y lee:

- `umbrel-app.yml`: nombre y puerto público de la app.
- `docker-compose.yml`: servicios, `ports`, `container_name` y `app_proxy`.
- `app-gateway.json`: destino resuelto por umbreld (`APP_HOST`, `APP_PORT`).
- `exports.sh`: solo valores `export KEY=value` estáticos, con regex. **Nunca se
  ejecuta.**

El destino preferido es el contenedor de `app_proxy` (el puerto web real). Los
puertos publicados explícitamente en compose se ofrecen como endpoints de
protocolo (P2P, RPC, etc.). Los servicios del host (SSH, panel HTTP/HTTPS) se
comprueban contra la puerta de enlace de la red Docker.

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
