# Cambios

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
