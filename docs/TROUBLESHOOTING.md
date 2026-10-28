# Diagnóstico

## La app no abre o pide login en bucle

- `app_proxy` mantiene el login de Umbrel. Inicia sesión en Umbrel primero.
- Después, la app pide `APP_PASSWORD`. Umbrel lo muestra en los detalles de la
  app porque el manifiesto usa `deterministicPassword: true`.
- Si cambiaste `APP_PASSWORD` o reinstalaste, cierra la sesión del navegador y
  vuelve a entrar.
- Revisa los logs del gateway:

  ```bash
  docker logs -f albercoin-store-umbrel-tunnel_gateway_1
  ```

## El túnel no tiene handshake

En el VPS:

```bash
sudo wg show
sudo systemctl status wg-quick@wg0 umbrel-tunnel
sudo journalctl -u wg-quick@wg0 -n 50 --no-pager
```

Comprueba:

- El endpoint del código `ut1` coincide con la IP pública y el puerto UDP
  (`51820/udp` por defecto).
- El firewall del proveedor y `ufw`/`firewalld` permiten ese UDP.
- La clave pública de Umbrel está registrada:

  ```bash
  sudo umbrel-tunnel peer list
  ```

- La subred del túnel no solapa con la red de Umbrel (`10.21.0.0/16`).

En Umbrel:

```bash
docker exec albercoin-store-umbrel-tunnel_gateway_1 wg show
docker exec albercoin-store-umbrel-tunnel_gateway_1 ip -4 addr show wg0
```

Si `wg0` no existe:

```bash
sudo modprobe wireguard
```

El contenedor necesita `NET_ADMIN` y, para cargar el módulo, `SYS_MODULE` con
`/lib/modules:ro` (ya está en el compose).

## La API del VPS no responde desde Umbrel

```bash
# Desde el contenedor del gateway
docker exec albercoin-store-umbrel-tunnel_gateway_1 wget -qO- http://10.0.0.1:8080/health
```

Si falla:

- ¿Hay handshake? Sin túnel no hay ruta a `10.0.0.1`.
- ¿La API escucha solo en el túnel? `ss -lntp | grep 8080` en el VPS debe
  mostrar `10.0.0.1:8080`, no `0.0.0.0:8080`.
- ¿El token es correcto? `sudo umbrel-tunnel token show`.
- ¿La URL guardada apunta a la IP del túnel? En **Configuración y diagnóstico → Opciones avanzadas** debe ser
  `http://10.0.0.1:8080`.

## El código `ut1` se rechaza

- Puedes pegar el bloque completo del instalador; la app extrae el primer
  `ut1.…`. Si pegas solo el código, debe empezar por `ut1.`.
- Si la app muestra `pair_bootstrap_mismatch`, el código no corresponde al
  comando que generó. Pulsa **Cambiar VPS**, genera un comando nuevo y
  ejecútalo, o revisa que no hayas emparejado con otro VPS.
- La URL de la API debe ser una IP dentro de la subred del túnel. Un código que
  apunte a `192.168.x.x`, `127.0.0.1` o un dominio se rechaza por seguridad.
- La subred no puede solaparse con `NETWORK_IP` de Umbrel.
- Si el código se generó antes de rotar el token, vuelve a ejecutar
  `umbrel-tunnel pair`. Si ya estás vinculado, basta actualizar el token en
  **Configuración y diagnóstico → Opciones avanzadas**, sin desvincular.

## Rotación WireGuard o desvinculación (1.4.1)

- Actualiza primero el VPS a 1.4.1. Los VPS anteriores no tienen la API de
  rotación coordinada; la app rechaza la operación sin sustituir la clave local.
- Durante la rotación habrá una interrupción breve. Si no se confirma el túnel
  nuevo, el VPS vuelve a la clave anterior al cabo de aproximadamente un minuto.
  Espera ese plazo antes de reintentar; revisa los logs de ambos extremos.
- Desvincular requiere acceso al VPS para retirar las publicaciones antes del
  peer. Si falla, las credenciales y el túnel se conservan para reintentar.
- Si el VPS ya no existe o es irrecuperable, acepta la segunda confirmación para
  olvidar la conexión **solo localmente**. No demuestra que las reglas remotas
  estén cerradas. Si el VPS sigue existiendo, entra por SSH, usa
  `umbrel-tunnel forward list --json`, elimina las reglas propias con
  `umbrel-tunnel forward rm ID` y después `umbrel-tunnel peer rm ID`.
- Para `peer config ID`, proporciona `--private-key-file RUTA` con la clave
  guardada al crear ese peer. No se puede reconstruir la privada desde la pública
  y una clave de otro peer se rechaza. La privada de Umbrel permanece en Umbrel.

## HAProxy no arranca o un puerto no responde

```bash
docker exec albercoin-store-umbrel-tunnel_gateway_1 haproxy -c -f /etc/haproxy/haproxy.cfg
docker exec albercoin-store-umbrel-tunnel_gateway_1 cat /data/haproxy.cfg
docker logs albercoin-store-umbrel-tunnel_gateway_1 | tail -50
```

Causas habituales:

- El destino no resuelve por DNS de Docker. Comprueba el nombre
  (`<app-id>_<servicio>_1`) y que la app esté en marcha.
- El puerto interno del túnel ya está en uso. La app asigna `20000–29999`; si se
  agota, cierra exposiciones.
- El contenedor de la app cambió de nombre o de puerto. Pulsa **Refrescar** en
  **Servicios**.

## Una app no aparece en la lista

- La detección lee `${UMBREL_ROOT}/app-data/<app-id>`. Comprueba que el
  contenedor ve ese árbol:

  ```bash
  docker exec albercoin-store-umbrel-tunnel_gateway_1 ls /umbrel-app-data
  ```

- Algunas apps no declaran `app_proxy` ni puertos publicados. Añade un servicio
  manual en **Servicios y puertos** con el nombre DNS del contenedor y el puerto.
- Pulsa **Refrescar**; la detección se cachea 15 segundos.

## El puerto público está ocupado o reservado

- El `22/tcp` del VPS está reservado. Para SSH de Umbrel usa otro puerto, por
  ejemplo `2222`.
- No repitas un puerto público entre exposiciones.
- En el VPS, comprueba qué está usando el puerto:

  ```bash
  sudo ss -lntup | grep :<PUERTO>
  sudo nft list table inet umbrel_tunnel
  ```

## La sincronización falla

En la app, **Puertos abiertos → Detalles** muestra el error. En el VPS:

```bash
sudo umbrel-tunnel forward list
sudo journalctl -u umbrel-tunnel -n 100 --no-pager
sudo umbrel-tunnel doctor
```

Si el VPS tiene forwards huérfanos con prefijo `umbrel:`, la app los limpia en
la siguiente sincronización. También puedes borrarlos a mano:

```bash
sudo umbrel-tunnel forward rm <id>
```

## Abrir un servicio manual falla

En **Servicios y puertos** cada fila muestra el estado real y, si hay
error, el detalle y un botón **Reintentar**. Antes de tocar el VPS, pulsa
**Configuración y diagnóstico → Comprobar ahora**; comprueba emparejamiento,
WireGuard, API del VPS, peer, forwards y HAProxy sin abrir ni cerrar puertos.

Mensajes habituales:

- **`public port ... already in use` (HTTP 409)**: otro forward usa ese puerto en
  el VPS. La app reintenta sola en un puerto libre y avisa del cambio. Si vuelve
  a fallar, elige un puerto distinto o revisa `umbrel-tunnel forward list`.
- **`target ... is not a peer` (HTTP 400)**: el `target_ip` del forward no es la
  IP del peer de Umbrel. Vuelve a emparejar o corrige el peer en el VPS.
- **`no se pudo contactar con el VPS`**: el túnel no está levantado o la API no
  responde. Revisa `wg show` y `systemctl status umbrel-tunnel`.
- **`proxy local: ...`**: el VPS sí creó el forward, pero HAProxy no arrancó o no
  pudo escribir su configuración. Revisa el log del contenedor:

  ```bash
  docker logs --tail 100 albercoin-store-umbrel-tunnel_gateway_1
  ```

  El destino debe resolver por DNS de Docker (`<app-id>_<servicio>_1`) y el
  puerto interno debe estar escuchando dentro del contenedor.
- **`service_not_found` / `manual_service_not_found`**: el servicio se borró o la
  detección aún no lo ve. Pulsa **Refrescar** y vuelve a añadirlo.

## `no se pudo aplicar nftables: ... specify 'dnat ip'`

Las versiones 1.0.0 y anteriores generaban `dnat to` dentro de una tabla
`inet`. nftables lo rechaza y el forward se revierte, así que el puerto nunca
llega a abrirse:

```
nft: /etc/umbrel-tunnel/rules.nft:19:42-45: Error: specify `dnat ip' or `dnat ip6' in inet table to disambiguate
```

Corregido en 1.0.1. Actualiza el binario del VPS (en arm64 usa `arm64`):

```bash
sudo umbrel-tunnel backup --output /root/umbrel-tunnel-backup.tar.gz
sudo umbrel-tunnel update \
  --from https://github.com/AlbercoinDev/umbrel-tunnel/releases/latest/download/umbrel-tunnel-linux-amd64
```

`update` verifica el `.sha256` publicado y reinicia el servicio. Al arrancar,
`Reconcile` reescribe `rules.nft`, de modo que el fichero inválido que dejó el
error desaparece. Después vuelve a activar la exposición en la app (el forward
se borró en el rollback) y comprueba:

```bash
umbrel-tunnel version          # 1.0.1
sudo nft list table inet umbrel_tunnel | grep dnat
sudo umbrel-tunnel forward list
```

## Idioma incorrecto

La primera visita usa `?lang=`, la cookie `ut_lang`, `Accept-Language` y luego
`UMBREL_LANG`/`LANG`. Usa el selector **ES/EN** de la cabecera o del login. La
preferencia se guarda en una cookie durante un año.

## El VPS no arranca tras actualizar

```bash
sudo umbrel-tunnel doctor
sudo systemctl status umbrel-tunnel
sudo journalctl -u umbrel-tunnel -n 100 --no-pager
sudo wg-quick down wg0 && sudo wg-quick up wg0
```

Puedes restaurar una copia:

```bash
sudo umbrel-tunnel restore --from /root/umbrel-tunnel-backup.tar.gz --force
```

## Recopilar información para un issue

```bash
umbrel-tunnel version
sudo umbrel-tunnel doctor --json
sudo wg show
sudo nft list table inet umbrel_tunnel
systemctl status umbrel-tunnel umbrel-tunnel-firewall wg-quick@wg0
```

No incluyas el token, claves privadas ni el código `ut1` completo en un issue.
