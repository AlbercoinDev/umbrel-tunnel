# Seguridad

## Modelo de confianza

- **VPS**: máquina del usuario con IP pública. Se asume que el proveedor y el
  sistema operativo están actualizados y que solo root accede por SSH.
- **Red de Docker de Umbrel**: no es de confianza. Cualquier contenedor de
  cualquier app puede intentar hablar con el gateway o con la API del VPS.
- **Navegador**: se accede a la app a través del proxy autenticado de Umbrel
  (`app_proxy` en 1.x, gateway in-process en 2.x) y del login propio con
  `APP_PASSWORD`.
- **Código `ut1`**: se trata como entrada no confiable.

## Superficie expuesta

### VPS

- Solo `wg0` puede alcanzar `10.0.0.1:8080`. nftables descarta el resto.
- El puerto UDP de WireGuard es el único servicio público además de los puertos
  que el usuario abra explícitamente.
- El `22/tcp` del VPS está reservado y no se puede abrir desde la app.
- La API exige `Authorization: Bearer <token>` salvo `/health`.
- El token se guarda en `/etc/umbrel-tunnel/token` (`600`) y se puede rotar.
- VPS compartido: cada Umbrel adicional es un nodo con token propio. El VPS
  guarda solo su SHA-256 en `peers.json` y lo acepta únicamente desde la IP del
  túnel de ese nodo. Un nodo solo lista, edita, comprueba y retira las
  publicaciones cuyo destino es su IP; el servidor fija `managed_by`; solo puede
  usar su dominio o subdominios; no puede crear peers ni tocar los ajenos. Las
  respuestas a recursos ajenos son `404`, sin revelar si existen.
- nftables descarta el tráfico `wg0 → wg0`: los peers no se alcanzan entre sí a
  través del VPS. El tráfico público (DNAT) y el edge HTTPS/TLS no se ven
  afectados.
- Mientras un Umbrel use el token de administración en un VPS compartido puede
  modificar las publicaciones de todos; `doctor` lo avisa hasta que se convierta
  con `peer claim` y se rote el token.

### Cadena de suministro

- Los binarios y los tarballs se publican con `SHA256SUMS` y una firma Ed25519
  (`SHA256SUMS.sig`) hecha con una clave que no está en GitHub.
- `install.sh` y `umbrel-tunnel update` verifican la firma con la clave pública
  embebida antes de ejecutar o instalar nada. Un SHA-256 servido junto al
  binario no se acepta como única prueba.
- La clave privada vive fuera del repositorio; el workflow solo la recibe como
  secreto al publicar un tag.
- `--allow-unsigned-checksum` es una excepción explícita para recuperación.
- `doctor` descarga `SHA256SUMS` y su firma de la release instalada, verifica la
  firma y compara el hash del binario en ejecución. Una firma inválida o un
  binario distinto se reportan como fallo; la falta de red, como aviso.
- El `install.sh` que ofrece la app viaja dentro de la imagen y se muestra con
  su SHA-256; no se descarga en el momento de la petición.

### App de Umbrel

- Umbrel mantiene su login (`app_proxy` en 1.x; gateway in-process en 2.x) y
  la app añade su propio login con `APP_PASSWORD` para que el control del túnel
  no dependa de una pieza que cambia entre versiones de umbrelOS.
- `/api/widget` es el único endpoint sin sesión: umbreld lo consulta sin cookies
  para el widget de la pantalla de inicio. Devuelve solo estado del túnel,
  número de servicios sanos y dominio base; nunca tokens, claves ni destinos.
- La cookie de sesión es HttpOnly, SameSite=Strict y firmada con un secreto
  persistente (`session.key`).
- Las peticiones mutantes exigen CSRF (`X-CSRF-Token` o campo de formulario).
- El login tiene límite de intentos por IP (5 en 5 minutos). Detrás de
  `app_proxy` todas las peticiones llegan con la IP del proxy, así que el límite
  es compartido: 5 fallos bloquean el login de todos durante 5 minutos. Se
  acepta a propósito; confiar en `X-Forwarded-For` permitiría a cualquier
  contenedor de la red de Docker saltarse el límite.
- El panel rechaza con 403 las peticiones cuyo origen está en la subred del
  túnel: ni el VPS ni otros peers WireGuard pueden usarlo aunque `10.0.0.2:8081`
  sea alcanzable por `wg0`. El resto de orígenes pasa por el login propio.
- La CSP es `script-src 'self'`; la configuración de la UI se pasa como JSON en
  un bloque `application/json`, no como script inline.
- Los errores no incluyen secretos; la configuración de WireGuard se muestra
  con `PrivateKey = <redacted>`.

### Cifrado en reposo

- `config.json` (token de la API, bootstrap y estado), la clave privada de
  WireGuard (`wireguard/private.key`), la copia persistente de `wg0.conf` y
  `rotation-pending.json` se guardan como sobres AES-256-GCM.
- La clave de 256 bits está en `data/secrets.key` (`0600`) y se deriva con
  scrypt (N=2^14, r=8, p=1, maxmem 64 MiB). Se calcula una vez por proceso.
- La clave viaja con el directorio de datos: una restauración de Umbrel sigue
  funcionando. Una copia completa del directorio también incluye la clave; el
  cifrado protege archivos sueltos, copias parciales y lectura accidental, no
  a quien controle todo el almacenamiento.
- `wg0.conf` en `/etc/wireguard` (capa efímera del contenedor) sigue en claro
  porque `wg-quick` lo necesita; nunca se escribe en `${APP_DATA_DIR}`.
- Al arrancar se migran solos los archivos heredados en texto plano. Si
  `secrets.key` falta o no coincide, la app falla de forma cerrada y no genera
  claves nuevas en silencio.

### Salud de las publicaciones

- Las sondas TCP/HTTP salen del gateway hacia destinos ya validados (mismos
  controles anti-SSRF) y corren en un hilo aparte con concurrencia limitada.
- Nunca se ejecutan en el camino de una petición del panel: la API solo lee una
  caché en memoria.
- No se guarda el resultado en `config.json`; un reinicio vuelve a medir.

### Destinos publicados (anti-SSRF)

- Se rechazan loopback, link-local (incluidos metadatos cloud), CGNAT
  (`100.64/10`), multicast, benchmarking y direcciones reservadas.
- Las direcciones privadas y los nombres de contenedor Docker se permiten para
  no romper servicios legítimos.
- Cada sincronización revalida el destino; si un nombre pasa a resolver a una
  red bloqueada se descarta solo esa publicación (rebinding).
- El relay UDP fija la IP aprobada al abrir la sesión (TTL 30 s) y no vuelve a
  resolver durante la sesión.

## Privilegios del contenedor

El contenedor parte de `cap_drop: ALL`. Solo recupera las capacidades que usa:

| Privilegio | Motivo |
| --- | --- |
| `NET_ADMIN` | crear `wg0`, asignar la IP del túnel y escuchar en ella con HAProxy |
| `SYS_MODULE` + `/lib/modules:ro` | cargar el módulo WireGuard del host en el primer arranque |
| `DAC_OVERRIDE` | escribir en `data`, que umbrelOS monta como `1000:1000`, sin ejecutar como root con todas las capacidades |
| `${UMBREL_ROOT}/app-data:ro` | detectar apps instaladas sin el socket de Docker |

No se monta el socket de Docker. No se usa `network_mode: host`. No se usa
`privileged: true`. `no-new-privileges:true` está activo.

La reducción se probó con una instalación nueva y con un upgrade desde 1.5.0:
sin `DAC_OVERRIDE` el proceso no puede crear `config.json` en un directorio
`1000:1000`, aunque sea root. Es un requisito de umbrelOS, no del gateway.

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

Los **servicios manuales** pasan además por `targets.validate`: se rechazan
loopback, link-local, multicast, direcciones reservadas y destinos que resuelven
a esos rangos. Las direcciones privadas y los nombres DNS de contenedores Docker
siguen permitidos. Un nombre que todavía no resuelve se acepta para no romper
apps que arrancan después; la comprobación se repite cuando el destino se
resuelve. No se bloquea por número de puerto: muchos servicios legítimos usan
8080/8443 y hacerlo rompería publicaciones existentes.

Además, el flujo app-first guarda un *bootstrap* pendiente con el token, el
endpoint, la URL de la API, la subred, la IP de Umbrel y el MTU. Al pegar el
código, la app rechaza (`pair_bootstrap_mismatch`) cualquier valor que no
coincida con ese bootstrap. El token del bootstrap se guarda en
`/data/config.json` (`600`) y se elimina al emparejar o desemparejar. El
comando de instalación se construye con `shlex.quote` porque se pega en una
shell de root.

## Auditoría

`data/audit.log` (`0600`, JSONL) registra login, emparejamiento, publicaciones,
servicios manuales, ajustes y rotaciones. Cada línea encadena el hash de la
anterior; `audit.verify()` se ejecuta en `GET /api/diagnostics` y detecta líneas
alteradas o borradas. Los tokens, contraseñas, claves privadas y códigos `ut1`
se redactan antes de escribir.

La cadena no protege frente a root ni frente a quien pueda reescribir el archivo
completo: es una ayuda de trazabilidad y detección, no un WORM. La rotación a
`audit.log.1` reinicia la cadena del archivo activo.

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
