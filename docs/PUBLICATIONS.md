# Publicaciones TCP/UDP y futura integración TLS

## Uso diario

La pantalla **Servicios y puertos** reúne servicios detectados y manuales.
Los filtros permiten ver todos, publicados, sin publicar o con errores.
Pausar conserva la publicación; dejar de publicar elimina su regla pública,
pero conserva el servicio. Un servicio manual sin publicación puede eliminarse.
Las publicaciones de servicios que ya no se detecten siguen visibles para
poder retirarlas. No se instala ni desinstala ninguna app desde esta pantalla.

**Configuración y diagnóstico** reúne la conexión al VPS, comprobaciones,
WireGuard y los ajustes de comunicación. La URL de API y el token se configuran
al vincular y no son la dirección pública de los servicios.

## Transporte UDP

El VPS aplica DNAT/SNAT UDP con nftables y envía los datagramas por WireGuard.
El gateway escucha en su dirección del túnel y utiliza un socket conectado por
cliente y publicación para devolver las respuestas al cliente correcto.
No se monta el socket de Docker ni se añaden privilegios al contenedor.

- Hasta 512 sesiones simultáneas en total; las nuevas se descartan al alcanzar
  el límite. Las sesiones inactivas caducan después de 60 segundos.
- El DNS del destino se resuelve al crear una sesión. Las sesiones existentes
  conservan su destino hasta caducar: un cambio de IP puede requerir esperar
  su caducidad o pausar/reanudar la publicación.
- Los nuevos listeners se preparan antes de sustituir los anteriores; un puerto
  ocupado no elimina los listeners que funcionaban.
- TCP y UDP pueden compartir número de puerto. El UDP de WireGuard está
  reservado; el 22/TCP se reserva para el SSH del VPS.
- TCP + UDP desde el formulario son dos publicaciones independientes, no una
  transacción atómica. Si falla una, la otra puede quedar creada.
- No se conserva la IP original del cliente en el destino.

UDP no tiene una comprobación genérica de «puerto abierto». Para validarlo hay
que enviar una solicitud válida de la aplicación desde fuera del VPS y comprobar
la respuesta. También hay que permitir el protocolo y puerto en el firewall del
proveedor. Las pruebas automatizadas locales no sustituyen esta prueba externa.

## Terminal del VPS

```sh
sudo umbrel-tunnel status
sudo umbrel-tunnel forward list --json
sudo umbrel-tunnel forward show ID
sudo umbrel-tunnel forward check ID
sudo umbrel-tunnel forward add --name ejemplo --public-port 9000 \
  --target-ip 10.0.0.2 --target-port 23000 --protocol udp
sudo umbrel-tunnel forward edit ID --public-port 9001
sudo umbrel-tunnel forward disable ID
sudo umbrel-tunnel forward enable ID
sudo umbrel-tunnel forward rm ID
sudo umbrel-tunnel forward reconcile
```

El daemon debe estar activo. Las mutaciones de publicaciones y peers pasan por
su API autenticada y se serializan, con las mismas validaciones que la app.
Los errores producen salida distinta de cero. `check` puede comprobar una
conexión TCP al destino del túnel, pero no afirma haber verificado Internet ni
el servicio detrás del proxy. En UDP informa de que necesita una prueba específica.

`managed_by` identifica reglas creadas por el VPS o por un peer de Umbrel.
Las reglas independientes del VPS no se eliminan al reconciliar Umbrel.
Se conserva compatibilidad con reglas antiguas identificadas por el prefijo
`umbrel:`; no utilices ese prefijo para reglas antiguas ajenas a la app.

Después de una sincronización correcta, Umbrel guarda los valores aplicados.
Si cambian en el VPS o desaparece la regla, detiene la reconciliación de esa
publicación y permite **Adoptar cambio del VPS** o **Restaurar desde Umbrel**.
Se pueden adoptar puerto y activación. Un cambio de destino o protocolo debe
restaurarse o configurarse como una publicación diferente; no se adopta a ciegas.
Adoptar una desactivación conserva la publicación local pausada y retira su
regla del VPS, igual que una pausa desde la app.

El VPS no puede descubrir ni configurar por sí solo los contenedores de Umbrel.
Crear un forward desde su terminal exige que el destino ya esté escuchando en
el peer. La administración remota de nuevos proxies de Umbrel requerirá un canal
de coordinación autenticado adicional; no se ha abierto una API nueva a Internet.

## Compatibilidad y despliegue

Actualiza el binario del VPS y la imagen del gateway conjuntamente: el gateway
envía el campo de propiedad `managed_by`, que las API antiguas no reconocen.
La versión 1.1.0 se distribuye con binarios amd64/arm64 y una imagen multiarch
fijada por digest en la tienda. Publicar esta versión no actualiza automáticamente
una instalación existente.

En Debian/Ubuntu, actualiza primero el VPS:

```sh
sudo umbrel-tunnel backup
sudo umbrel-tunnel update
umbrel-tunnel version
sudo umbrel-tunnel doctor
```

Comprueba que la copia se creó antes de continuar. `update` conserva la
configuración y reinicia el servicio. Después actualiza la app a 1.1.0 desde la
tienda de Umbrel, sin desinstalar ni volver a vincular.

## Dominios, HTTPS y TLS

Las publicaciones conservan TCP/UDP directo por defecto. Configura el dominio
base opcional en **Configuración y diagnóstico** y usa **Añadir publicación** en
la fila de cada servicio. El formulario reúne dominio, puerto y cifrado. Un mismo
destino permite varias entradas independientes, como Electrs con el mismo dominio
en 50001 sin TLS y 50002 con TLS, ambas hacia el puerto interno 50001.
Las entradas existentes se conservan; cambiar el dominio base no las reescribe.

- `https`: varios dominios comparten 443; el VPS termina HTTPS y conecta por HTTP
  al servicio a través del proxy local de Umbrel y WireGuard.
- `tls`: un puerto TCP dedicado termina TLS en el VPS; por ejemplo,
  `electrs.umbrel.nodobitcoin.org:50002` conecta con Electrs TCP en 50001.
- `http`: proxy web por dominio sin certificado; varios nombres pueden compartir
  el puerto. TCP/UDP directo también admite un dominio como dirección pública,
  pero no puede multiplexar destinos por nombre en el mismo puerto.
- Los certificados individuales de Let's Encrypt se emiten y renuevan con ACME.
  No se solicitan certificados wildcard ni credenciales DNS.

El proveedor DNS debe permitir un registro wildcard hacia el VPS. El puerto 80
debe permanecer accesible para HTTP-01; con Cloudflare usa **Solo DNS**.
La app no cambia automáticamente DNS, reglas del proveedor ni las opciones
particulares de cada servicio. Consulta [TLS.md](TLS.md) para configuración,
actualización segura, pruebas y límites.

WireGuard protege VPS–Umbrel; el acceso directo sigue sin añadir cifrado.
Los certificados no sustituyen la autenticación de las aplicaciones.
