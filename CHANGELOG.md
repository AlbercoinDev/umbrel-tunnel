# Cambios

## 1.6.2

- Salud real por publicación: sonda TCP cada 60 s desde el gateway, con
  latencia y detalle del error. Las publicaciones web comprueban además que el
  destino responde HTTP; un servicio no HTTP sigue contando como sano.
- UDP se muestra como "sin datos": no existe una sonda fiable sin conocer el
  protocolo, así que no se finge un estado.
- El panel, `/api/diagnostics` y el widget usan el resultado real. Si aún no
  hay datos, el widget muestra `—` en vez de un cero engañoso.
- Las sondas corren en segundo plano (`UMBREL_TUNNEL_HEALTH=0` las desactiva) y
  nunca hacen red en el camino de una petición.
- VPS sin cambios; no hace falta actualizarlo.

## 1.6.1

- `data/secrets.key` falla de forma cerrada si existe pero está corrupto o no
  se puede leer: no se genera otra clave que dejaría los datos ilegibles.
- Sin cambios de comportamiento, manifiesto ni VPS respecto a 1.6.0.

## 1.6.0

- Seguridad: `config.json`, la clave privada de WireGuard, la copia persistente
  de `wg0.conf` y la rotación pendiente se guardan cifrados con AES-256-GCM.
  La clave vive en `data/secrets.key` (`0600`), se deriva con scrypt y viaja con
  los datos para no romper restauraciones. Los archivos en texto plano se
  migran automáticamente al arrancar.
- Seguridad: los destinos manuales se revalidan en cada sincronización y el
  relay UDP fija una IP aprobada por sesión (anti-rebinding). Se bloquean
  además CGNAT (`100.64/10`, incluidos metadatos cloud), `192.0.0.0/24` y
  `198.18.0.0/15`.
- umbrelOS 2.x: la app funciona con el gateway in-process, sin `app_proxy`, y
  añade el widget de pantalla de inicio (`three-stats`: estado del túnel,
  servicios sanos y dominio público).
- `data/haproxy.cfg` queda fuera de las copias de seguridad de Umbrel por ser
  regenerable.
- VPS: sin cambios de código; los binarios se recompilan con el mismo Go
  1.27.4. No hace falta actualizar el VPS.

## 1.5.4

- VPS: binarios recompilados con Go 1.27.4, la rama estable actual.
- Gateway: sin cambios de código ni de dependencias; mantiene Alpine 3.24 y
  Python 3.14.
- Sin cambios funcionales en emparejamiento, detección, publicaciones,
  certificados, capacidades ni auditoría.

## 1.5.3

- Gateway: base Alpine 3.24 y Python 3.14 del sistema, con las correcciones de
  paquetes de la rama estable actual.
- VPS: sin cambios de código; binarios recompilados con Go 1.26.11.
- Sin cambios funcionales en emparejamiento, detección, publicaciones,
  certificados, capacidades ni auditoría.

## 1.5.2

- Gateway: imagen reconstruida sobre el digest vigente de Alpine 3.22 para
  incorporar las correcciones de paquetes del sistema.
- VPS: binarios recompilados con Go 1.26.11 y `golang.org/x/crypto` 0.59.0 /
  `golang.org/x/net` 0.62.0.
- Sin cambios funcionales en emparejamiento, detección, publicaciones,
  certificados, capacidades ni auditoría.

## 1.5.1

- Gateway: el contenedor parte de `cap_drop: ALL` y solo recupera `NET_ADMIN`,
  `SYS_MODULE` y `DAC_OVERRIDE`. `DAC_OVERRIDE` es necesario porque umbrelOS
  monta `data` como `1000:1000`; sin él una instalación nueva no puede escribir
  la configuración.
- Servicios manuales: se rechazan destinos de loopback, link-local (metadatos
  cloud), multicast y direcciones reservadas. Las direcciones privadas y los
  nombres de contenedor Docker siguen permitidos, y un nombre que aún no
  resuelve se acepta para no romper apps que arrancan después.
- Auditoría: `data/audit.log` (0600, JSONL) con cadena de hashes para login,
  emparejamiento, publicaciones, servicios manuales, ajustes y rotaciones.
  `GET /api/diagnostics` incluye el resultado de `audit.verify()`.
- CI: `govulncheck`, `bandit` (alta severidad), comprobación de sintaxis de los
  scripts y Dependabot para Go, Docker y Actions.

## 1.5.0

- VPS compartido: varios Umbrel pueden usar el mismo VPS, cada uno con su
  dominio público. Dos Umbrel pueden publicar la misma app en el mismo puerto
  (HTTPS en 443 o TLS como Electrum en 50002) y el VPS enruta por dominio.
- Nodos: un peer con `domain` y token propio (`token_sha256` en `peers.json`).
  El token solo vale desde su IP del túnel; el nodo solo ve y cambia las
  publicaciones hacia su IP y solo usa su dominio o subdominios. El token de
  administración conserva el acceso total.
- TLS añadido: el edge elige la publicación por SNI, de modo que varios
  dominios comparten un puerto. Sin SNI solo se atiende un puerto no compartido.
- nftables descarta el tráfico `wg0 → wg0`: los Umbrel no se alcanzan entre sí.
- CLI: `peer add --domain [--token]` asigna IP libre e imprime el `ut1` del
  nodo; `peer claim ID --domain` convierte el Umbrel original. `doctor` avisa si
  conviven nodos con un Umbrel que aún usa el token de administración.
- App: campo opcional "VPS compartido" en la configuración inicial, que genera
  `umbrel-tunnel peer add`; el dominio del `ut1` pasa a ser el dominio base y no
  se pueden usar dominios fuera de él.
- Las instalaciones de un solo Umbrel no cambian.

## 1.4.2

- Gateway: el panel rechaza (403) cualquier petición que llegue por la subred
  WireGuard. Waitress escucha en todas las interfaces y, con `AllowedIPs` de la
  subred completa, el VPS u otro peer podían alcanzar `10.0.0.2:8081` sin pasar
  por `app_proxy`.
- Instalador del VPS: verifica el binario descargado con el `.sha256` publicado
  junto a él y se detiene si falta o no coincide. El comando generado por la app
  fija script y binario al tag de la release (`v1.4.2`) en lugar de `main` y
  `releases/latest`.
- Estado: un `config.json` corrupto ya no se sustituye por valores por defecto
  (lo que borraba vinculación, token y publicaciones al siguiente guardado). Se
  usa la copia `config.json.bak` o se responde 503 sin tocar el archivo.
- Retirar una publicación toma el bloqueo de sincronización, para que una
  sincronización en curso no la vuelva a crear en el VPS; las llamadas de red
  de retirar y vincular ya no retienen el bloqueo del estado.
- Rotación WireGuard: si el gateway se reinicia entre preparar y confirmar, al
  arrancar confirma la rotación o restaura la clave anterior.

## 1.4.1

- Rotación WireGuard coordinada entre Umbrel y VPS: preparación por el túnel
  anterior, confirmación por el nuevo y rollback automático si no se confirma.
- Desvinculación: limpiar las publicaciones antes de retirar el peer; conservar
  credenciales ante errores y permitir olvido local solo con confirmación explícita.
- `peer config ID --private-key-file RUTA`: verificar que la privada suministrada
  corresponde al peer. No se almacenan nuevas claves privadas de cliente en el VPS.
- Panel VPS: crear publicaciones UDP en modo directo y explicar cómo actualizar
  el token en Umbrel sin desvincular.
- API VPS: errores de aplicación con `code` y `error`; documentación de todas las
  rutas de certificados, comprobación, reconciliación y rotación.
- Instalación alternativa: prerregistrar la clave pública y usar el token del
  asistente. `push.sh` acepta `--token` y conserva los argumentos por SSH sin
  dividirlos ni evaluarlos como comandos.
- Documentación de toolchain, versiones, actualizaciones y límites de cada mitad
  alineada con la implementación; nuevas pruebas de conexión y rotación.

### Actualización

Actualiza **primero el VPS**, después la app de Umbrel a 1.4.1:

```sh
sudo umbrel-tunnel backup --output /root/umbrel-tunnel-before-1.4.1.tar.gz
sudo umbrel-tunnel update
umbrel-tunnel version
sudo umbrel-tunnel doctor
```

Desde un VPS anterior a 1.3.2, usa `update --from` con la URL del binario de su
arquitectura, como explica el README. No desinstales, borres datos ni vuelvas a
vincular para actualizar. El gateway anterior sigue funcionando con el VPS nuevo;
rotar desde el gateway 1.4.1 requiere el VPS 1.4.1.
