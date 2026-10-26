# Seguridad

## Modelo de confianza

- **VPS**: máquina del usuario con IP pública. Se asume que el proveedor y el
  sistema operativo están actualizados y que solo root accede por SSH.
- **Red de Docker de Umbrel**: no es de confianza. Cualquier contenedor de
  cualquier app puede intentar hablar con el gateway o con la API del VPS.
- **Navegador**: se accede a la app a través de `app_proxy` (login de Umbrel) y
  del login propio con `APP_PASSWORD`.
- **Código `ut1`**: se trata como entrada no confiable.

## Superficie expuesta

### VPS

- Solo `wg0` puede alcanzar `10.0.0.1:8080`. nftables descarta el resto.
- El puerto UDP de WireGuard es el único servicio público además de los puertos
  que el usuario abra explícitamente.
- El `22/tcp` del VPS está reservado y no se puede abrir desde la app.
- La API exige `Authorization: Bearer <token>` salvo `/health`.
- El token se guarda en `/etc/umbrel-tunnel/token` (`600`) y se puede rotar.

### App de Umbrel

- `app_proxy` mantiene el login de Umbrel activo. La app añade su propio login
  con `APP_PASSWORD` para que el control del túnel no dependa solo de la sesión
  de Umbrel.
- La cookie de sesión es HttpOnly, SameSite=Strict y firmada con un secreto
  persistente (`session.key`).
- Las peticiones mutantes exigen CSRF (`X-CSRF-Token` o campo de formulario).
- El login tiene límite de intentos por IP (5 en 5 minutos).
- La CSP es `script-src 'self'`; la configuración de la UI se pasa como JSON en
  un bloque `application/json`, no como script inline.
- Los errores no incluyen secretos; la configuración de WireGuard se muestra
  con `PrivateKey = <redacted>`.

## Privilegios del contenedor

El gateway necesita privilegios de host poco habituales. Están limitados y
justificados:

| Privilegio | Motivo |
| --- | --- |
| `NET_ADMIN` | crear `wg0`, asignar la IP del túnel y escuchar en ella con HAProxy |
| `SYS_MODULE` + `/lib/modules:ro` | cargar el módulo WireGuard del host en el primer arranque |
| `${UMBREL_ROOT}/app-data:ro` | detectar apps instaladas sin el socket de Docker |

No se monta el socket de Docker. No se usa `network_mode: host`. No se usa
`privileged: true`. `no-new-privileges:true` está activo.

El montaje de `app-data` es el privilegio más amplio: permite leer manifiestos y
compose de otras apps. El código solo lee archivos regulares, rechaza symlinks,
limita el tamaño a 512 KiB y nunca ejecuta `exports.sh` ni devuelve variables de
entorno. Si un despliegue requiere un modelo más estricto, se puede sustituir
por una lista de apps montadas una a una, a costa de perder la detección
automática de apps nuevas.

## WireGuard

- La clave privada de Umbrel se genera y se guarda en el contenedor
  (`/data/wireguard/private.key`, `600`). Nunca se envía al VPS ni se incluye en
  el código de emparejamiento.
- El VPS solo almacena claves públicas.
- La configuración se construye desde campos estructurados. El parser rechaza
  directivas desconocidas y, en especial, hooks que ejecutarían comandos como
  root: `PostUp`, `PostDown`, `PreUp`, `PreDown`, `SaveConfig`, etc.
- Se valida la subred, la IP del túnel, el endpoint, el MTU y las claves.
- La subred del túnel no puede solaparse con `NETWORK_IP` de Umbrel.

## SSRF y validación de la API

Un código `ut1` malicioso podría intentar apuntar el gateway a un host interno.
Por eso `validate_api_url` exige:

- esquema `http` o `https`;
- host expresado como IP;
- IP dentro de la subred del túnel;
- puerto válido;
- sin usuario/contraseña embebidos.

La misma validación se aplica al cambiar la URL desde **Avanzado** cuando ya se
conoce la subred.

## Recomendaciones operativas

- Mantén el VPS actualizado y limita SSH por clave.
- Rota el token si sospechas que se ha filtrado: `umbrel-tunnel token rotate`.
- Rota la clave de WireGuard desde la app si cambias de dispositivo o sospechas
  de una copia del contenedor.
- No uses `--public-api`.
- No expongas servicios sensibles (RPC de Bitcoin, LND, bases de datos,
  Portainer, SSH) sin autenticación adicional y firewall.
- Revisa los forwards abiertos con `umbrel-tunnel forward list` y desde la app.

## Notificar una vulnerabilidad

Abre un issue privado o contacta al mantenedor del repositorio. No publiques
detalles explotables antes de que haya un parche.
