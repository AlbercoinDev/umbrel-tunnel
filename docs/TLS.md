# Dominios, HTTPS y TLS TCP

## Requisitos y DNS

La funcionalidad es opcional. Sin publicaciones HTTPS/TLS configuradas no se
reservan sus puertos ni se inicia emisión ACME. Se puede configurar después de
vincular el VPS, sin reinstalar ni generar otras claves WireGuard.

El usuario debe disponer de un dominio y de un proveedor DNS que permita crear
un registro wildcard. Por ejemplo, en Cloudflare:

| Tipo | Nombre | Contenido | Proxy |
| --- | --- | --- | --- |
| A | `umbrel` | IPv4 pública del VPS | Solo DNS (nube gris) |
| A | `*.umbrel` | IPv4 pública del VPS | Solo DNS (nube gris) |

Un CNAME wildcard al nombre base también es válido. No publiques AAAA salvo que
IPv6 llegue realmente al mismo VPS y a los listeners: una AAAA incorrecta puede
impedir la validación ACME. Los registros CAA, si existen, deben autorizar a
`letsencrypt.org`. DNS y firewalls del proveedor no se modifican desde la app.

El wildcard **DNS** no es un certificado wildcard: se obtiene un certificado
individual por nombre publicado mediante HTTP-01, sin token de Cloudflare.
Los nombres aparecerán en los registros públicos de Certificate Transparency.
El DNS por sí solo no decide puertos. Para TCP no HTTP debes configurar el
hostname, el puerto público y TLS en el cliente.

Permite TCP 80 para emisión **y renovación**, TCP 443 si usas HTTPS y cada puerto
TLS dedicado, además de WireGuard. El puerto 80 solo sirve desafíos ACME y
redirecciones a dominios HTTPS configurados; no da acceso al backend en HTTP.
Los puertos 80/443 quedan reservados frente a DNAT TCP mientras haya alguna
publicación web HTTP/HTTPS o TLS configurada, incluso pausada. Un conflicto se rechaza,
nunca se elimina una regla ajena ni se busca otro puerto TLS silenciosamente.

## Configuración desde Umbrel

1. Vincula el VPS normalmente. Puedes omitir TLS durante la instalación.
2. En **Configuración y diagnóstico → Dominio base y certificados**, guarda
   `umbrel.nodobitcoin.org`. No abre puertos ni solicita certificados. Cambiarlo
   después no reescribe nombres completos de publicaciones existentes.
3. Si el servicio no aparece, usa **Añadir servicio manual → Solo añadir**.
4. En la fila del servicio, pulsa **Añadir publicación**. Configura por separado
   puerto público, dominio opcional, tipo TCP/UDP o web HTTP y terminación TLS
   opcional. Web + TLS usa HTTPS en 443; TCP + TLS usa un puerto dedicado.
   El destino habla HTTP o TCP sin TLS respectivamente. El subdominio vacío
   permite usar el propio dominio base.
5. Si activas TLS, acepta las condiciones de Let's Encrypt. Confirma la
   publicación en Internet y revisa el resumen dirección:puerto → destino.
6. Guarda. **Añadir crea una publicación independiente, no sustituye otra del
   servicio**. Usa **Editar** para cambiar una entrada existente. Cada entrada
   permite pausar, reanudar o dejar de publicar. Los puertos elegidos no se
   sustituyen automáticamente si hay un conflicto.
7. Consulta el estado del certificado en la fila o en Configuración; la primera
   emisión puede tardar minutos.
   **Reintentar emisión** programa otra comprobación con límite por dominio;
   no borra certificados ni fuerza reemisiones de certificados válidos.

Los controles habituales permiten pausar/reanudar o dejar de publicar. Pausar
retira el listener/ruta pública, pero conserva la configuración y la caché de
certificados. Las conexiones TCP ya establecidas pueden continuar hasta cerrarse.
Al reiniciar, el daemon carga la configuración y activa de nuevo
la renovación de los certificados habilitados, sin necesitar tráfico del usuario.
Las conexiones TCP existentes no se cortan por renovar el certificado.

La configuración de una publicación indica intención, **no** que la CA haya
emitido el certificado ni que el servicio sea accesible desde Internet.
Comprueba por separado sincronización, certificado y respuesta de la aplicación.

### Dominio sin certificado

Un nombre DNS no implica TLS ni decide el puerto. Puedes publicar TCP/UDP directo
con o sin dominio, sin añadir cifrado. El TLS propio del servicio se conserva
si ya existe. Para varios sitios web en el mismo puerto, elige tipo web HTTP
sin marcar TLS: el VPS enruta por Host, sin solicitar certificados. HTTP en 80
puede convivir con ACME. Una entrada HTTP explícita para un nombre sirve HTTP;
si solo existe HTTPS, el 80 redirige a HTTPS como antes.

TCP/UDP directo no distingue subdominios para repartir la misma IP y puerto
entre destinos: requiere puertos diferentes. Las publicaciones web sí pueden
compartir puerto con nombres distintos. Los conflictos se rechazan.

### PrivateBin

Publica `privatebin.umbrel.nodobitcoin.org` en modo HTTPS hacia su servicio HTTP.
El navegador recibe HTTPS y puede usar las APIs que requieren un contexto seguro.
El proxy conserva Host y establece `X-Forwarded-Proto: https`,
`X-Forwarded-Host` y `X-Forwarded-For`, descartando cabeceras reenviadas falsas.
Algunas aplicaciones necesitan configurar su URL pública o sus proxies de
confianza: esto depende de cada app y no se cambia automáticamente.

### Electrs

Añade un servicio manual con el host/contenedor real de Electrs y puerto 50001,
TCP, **Solo añadir**. Añade una publicación TCP sin TLS con subdominio `electrs`
y puerto público 50001. Añade otra al **mismo servicio**, marcando TLS y usando
el mismo subdominio y puerto público 50002. Ambas apuntan al destino interno
50001; no necesitas duplicar el servicio ni crear otro túnel. La entrada 50001
va en claro entre Internet y el VPS por decisión explícita. Configura la cartera con
ese hostname, puerto 50002 y SSL/TLS activado. El VPS admite clientes sin SNI en
el puerto dedicado; si envían SNI, debe coincidir con su dominio configurado.

```
Internet --TLS :50002--> VPS --TCP sobre WireGuard--> Umbrel --TCP--> Electrs :50001
```

El tramo interno contenedor gateway–servicio mantiene su transporte actual en
la red Docker de Umbrel; WireGuard protege el enlace VPS–gateway, no toda la LAN.

## VPS: CLI, API y panel

Los modos se guardan en las publicaciones existentes (`access_mode`, `domain`),
pero las publicaciones cifradas no generan DNAT: usan listeners y proxy en el
daemon. Pueden compartir 443 si sus dominios son distintos. Un puerto TLS TCP
es exclusivo; no hay multiplexación TCP por SNI en un mismo puerto.

```sh
# El destino debe estar escuchando ya dentro del túnel. Los números 20000/20001
# son ejemplos de listeners de HAProxy, NO los puertos del contenedor remoto.
sudo umbrel-tunnel forward add --name privatebin --access-mode https \
  --domain privatebin.umbrel.nodobitcoin.org --public-port 443 \
  --target-ip 10.0.0.2 --target-port 20000 --accept-acme-terms
sudo umbrel-tunnel forward add --name electrs --access-mode tls \
  --domain electrs.umbrel.nodobitcoin.org --public-port 50002 \
  --target-ip 10.0.0.2 --target-port 20001 --accept-acme-terms
sudo umbrel-tunnel certificates
sudo umbrel-tunnel certificates retry
```

`forward edit ID` admite `--access-mode`, `--domain`, `--public-port` y
`--accept-acme-terms`. Cambiar desde TLS a directo requiere indicar
`--access-mode direct --domain ''` y elegir conscientemente el puerto en claro.
Si la publicación pertenece a Umbrel, modifica desde la app o resuelve después
el conflicto: los cambios externos no se sobrescriben sin confirmación.

API autenticada dentro del túnel:

- `POST /api/forwards` y `PATCH /api/forwards/{id}`: campos `access_mode`
  (`direct`, `http`, `https`, `tls`), `domain` y `accept_acme_terms: true` al activar o
  cambiar nombre/modo cifrado. UDP no admite estos modos.
- `GET /api/certificates`: `domain`, `enabled`, `state`, `not_after`, `error`.
  Estados `pending`, `ready`, `expiring` (menos de 14 días), `expired`.
- `POST /api/certificates/retry`: programa un reintento, HTTP 202.

API local de Umbrel: `POST /api/settings` acepta `base_domain`; `POST /api/exposures`
acepta `new_publication: true` para añadir sin deduplicar por destino, `subdomain`
(resuelto contra el dominio base), `access_mode` y `public_port`. La configuración
guarda nombres completos para preservar las publicaciones al cambiar el dominio
base. Los clientes antiguos conservan la deduplicación si no solicitan una nueva
publicación. Editar usa `PATCH /api/exposures/{id}`.

El panel privado del VPS también permite crear publicaciones cifradas y ver
certificados. No descubre ni crea proxies de Umbrel: para publicar contenedores
es preferible la app. La API de control no se publica bajo ningún dominio HTTPS.

## Actualización y seguridad operativa

Actualiza **VPS y gateway conjuntamente**. Los binarios antiguos no conocen los
campos nuevos. Antes de actualizar, haz una copia de seguridad verificable.
Si vienes de una versión anterior a 1.2.0, actualiza también la unidad systemd:
`CAP_NET_BIND_SERVICE` permite escuchar en 80/443 bajo el endurecimiento existente.
**Sustituir solo el binario con `update` no actualiza dicha unidad**. Reejecuta el
instalador de **1.3.0** (sin `--force`, sin `--purge`), que conserva configuración
y claves. El siguiente bloque hace backup, descarga el paquete de tu arquitectura,
verifica su checksum y actualiza binario y unidades systemd. Se interrumpe si falla
algún paso. El túnel y las publicaciones tendrán una interrupción breve.

Ejecuta en el VPS antes de actualizar la app de Umbrel:

```sh
sudo bash <<'SH'
set -euo pipefail
backup="/root/umbrel-tunnel-before-1.3.0-$(date +%Y%m%d-%H%M%S).tar.gz"
umbrel-tunnel backup --output "$backup"
test -s "$backup"
arch="$(dpkg --print-architecture)"
case "$arch" in amd64|arm64) ;; *) echo "Arquitectura no soportada: $arch" >&2; exit 1 ;; esac
work="$(mktemp -d /root/umbrel-tunnel-upgrade-1.3.0.XXXXXX)"
cd "$work"
base="https://github.com/AlbercoinDev/umbrel-tunnel/releases/download/v1.3.0"
file="umbrel-tunnel-1.3.0-linux-$arch.tar.gz"
curl -fLsS --retry 2 "$base/$file" -o "$file"
curl -fLsS --retry 2 "$base/SHA256SUMS" -o SHA256SUMS
grep -F "  $file" SHA256SUMS | sha256sum --check --strict -
tar -xzf "$file"
cd "umbrel-tunnel-1.3.0-linux-$arch"
bash ./install.sh
umbrel-tunnel version
umbrel-tunnel doctor
systemctl is-active umbrel-tunnel wg-quick@wg0 umbrel-tunnel-firewall
echo "Backup conservado: $backup"
SH
```

Después actualiza **Umbrel Tunnel a 1.3.0** desde la tienda de Umbrel. No
desinstales, no borres los datos y no vuelvas a vincular el VPS. En instalaciones
con puertos de API/WireGuard personalizados, pasa los mismos valores al instalador
(`--api-port`, `--wg-port`) para que sus comprobaciones utilicen los puertos reales.

Compilación: Go 1.26 o posterior, con dependencias ACME fijadas en `go.mod/go.sum`.
No se añade Docker, Certbot ni otro daemon al VPS.

Claves ACME y certificados quedan en
`/var/lib/umbrel-tunnel/certificates/` con directorios privados y archivos 0600.
La copia de seguridad incluye estos secretos: protégela igual que WireGuard.
La app recibe solo metadatos públicos, nunca las claves. Mantén el daemon activo
y DNS/80 accesibles para renovar. No borres la caché para resolver errores: puede
provocar límites de emisión de la CA. Los errores de renovación de ACME también
se consultan en `journalctl -u umbrel-tunnel`.

Los servicios quedan accesibles desde Internet: HTTPS no añade contraseña ni
hace seguro un RPC sensible. No se soportan STARTTLS, TLS sobre UDP, certificados
importados ni certificados wildcard/DNS-01. Para TLS gestionado por el servicio,
TCP directo conserva su cifrado extremo a extremo (passthrough de bytes).

## Pruebas antes de producción

Las pruebas automatizadas usan certificados locales y proxies de loopback: no
modifican DNS, WireGuard o nftables reales ni solicitan certificados públicos.
Para probar la emisión/renovación real en un VPS de pruebas, configura un override
systemd con `Environment=UMBREL_TUNNEL_ACME_STAGING=1`, recarga systemd y reinicia.
Staging utiliza una caché independiente `certificates-staging/`, cuyos certificados
no son de confianza. Al quitar el override y reiniciar se usa producción.
No mezcles staging con la instalación de uso diario sin una ventana de pruebas.

Desde otra conexión a Internet:

```sh
curl -I https://privatebin.umbrel.nodobitcoin.org
openssl s_client -connect electrs.umbrel.nodobitcoin.org:50002 \
  -servername electrs.umbrel.nodobitcoin.org \
  -verify_hostname electrs.umbrel.nodobitcoin.org -verify_return_error
```

Verifica cadena y nombre, respuesta de PrivateBin, una consulta Electrum real,
rechazo de nombres no configurados, reinicio del VPS y estado de renovación.
Staging permite validar el flujo ACME, pero no sustituye una prueba real ni
demuestra por sí solo una renovación tras semanas de funcionamiento.
