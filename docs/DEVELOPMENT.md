# Desarrollo

## Requisitos

- Go 1.22+ para el VPS.
- Python 3.11+ para el gateway.
- Docker + buildx para la imagen del gateway.
- Node 20+ solo si quieres ejecutar el linter oficial de Umbrel.

## VPS

```bash
cd vps
gofmt -w .
go vet ./...
go test ./...
make dist
```

`make dist` genera en `vps/dist/`:

- `umbrel-tunnel-linux-amd64`
- `umbrel-tunnel-linux-arm64`
- tarballs con `install.sh`, `VERSION` y `packaging/` (copia de `internal/units/files/`)
- `SHA256SUMS`

Prueba el instalador sin tocar el sistema:

```bash
unshare -r env UMBREL_TUNNEL_OS_RELEASE=/tmp/opencode/os-release-test \
  ./install.sh --dry-run --endpoint 203.0.113.10 --wg-port 51899 \
  --binary dist/umbrel-tunnel-linux-amd64
```

## Gateway

```bash
cd umbrel-tunnel/gateway
python3 -m venv .venv
. .venv/bin/activate
pip install flask pyyaml waitress

python3 -m py_compile app.py catalog.py detect.py i18n.py proxy.py serve.py state.py sync.py vps.py wireguard.py
python3 -m unittest discover -s tests -v
```

Los tests usan directorios temporales y variables de entorno
(`UMBREL_TUNNEL_DATA`, `UMBREL_APP_DATA`, `UMBREL_TUNNEL_WG_CONF`,
`UMBREL_TUNNEL_HAPROXY_CONF`, `UMBREL_TUNNEL_HAPROXY_PID`) para no tocar el
host. Cubren:

- paridad de claves i18n y resolución de idioma;
- generación/validación estricta de WireGuard;
- detección desde `app-data`, `app-gateway.json` y `exports.sh` sin ejecutarlo;
- login, CSRF, rate limit y CSP;
- validación de la URL de la API del código `ut1`.

### Ejecución local

```bash
UMBREL_TUNNEL_DEV=1 \
UMBREL_TUNNEL_DATA=/tmp/umbrel-tunnel-data \
UMBREL_APP_DATA=/tmp/umbrel-app-data \
PORT=8081 \
python3 serve.py
```

Abre `http://127.0.0.1:8081` y usa la contraseña `dev`. Sin Docker no se puede
crear `wg0` ni arrancar HAProxy, pero la UI, la detección y la API funcionan.

### Imagen

```bash
cd umbrel-tunnel/gateway
docker build -t umbrel-tunnel-gateway:dev .
docker run --rm -p 8081:8081 \
  -e UMBREL_TUNNEL_DEV=1 \
  -e UMBREL_TUNNEL_DATA=/data \
  -v /tmp/umbrel-tunnel-data:/data \
  umbrel-tunnel-gateway:dev
```

La imagen base está fijada por digest en el `Dockerfile`. Actualízala solo tras
probar la nueva versión.

## Publicar la imagen del gateway

El compose de la tienda **no usa `build:`**. Umbrel descarga una imagen ya
publicada. El workflow `.github/workflows/gateway-image.yml` construye y publica
`linux/amd64` + `linux/arm64` en GHCR cuando se empuja un tag `v*`:

```bash
git tag v1.0.0
git push origin v1.0.0
```

El workflow publica `ghcr.io/albercoindev/umbrel-tunnel-gateway:1.0.0` y
`:latest`. Después:

1. Haz público el paquete en **GitHub → Packages → umbrel-tunnel-gateway →
   Package settings → Change visibility**.
2. Obtén el digest del índice multi-arquitectura:

   ```bash
   docker buildx imagetools inspect \
     ghcr.io/albercoindev/umbrel-tunnel-gateway:1.0.0
   ```

3. Fija imagen + digest en `umbrel-tunnel/docker-compose.yml`:

   ```yaml
   image: ghcr.io/albercoindev/umbrel-tunnel-gateway:1.0.0@sha256:<DIGEST>
   ```

4. Sube el cambio. El linter oficial de Umbrel exige etiqueta **y** digest; sin
   el digest reporta `image.pinned`.

## Linter de Umbrel

```bash
git clone --depth 1 https://github.com/getumbrel/umbrel-apps /tmp/umbrel-apps
cd /tmp/umbrel-apps
npm install
UMBREL_APP_LINT_ROOT=/ruta/a/Umbrel-AppStore-Albercoin \
  node .tools/lint-apps.mjs albercoin-store-umbrel-tunnel --format text
```

Avisos esperados y justificados:

- `access.cap_add`: `NET_ADMIN` y `SYS_MODULE` son necesarios para WireGuard.
- `access.host_mount`: `/lib/modules:ro` solo se usa para `modprobe`.
- `access.security_opt`: `no-new-privileges` es una medida de seguridad, no un
  privilegio.

## Community App Store

Este repositorio contiene el código, la documentación y las releases del plano
de control. La app se distribuye desde la tienda
[`AlbercoinDev/Umbrel-AppStore-Albercoin`](https://github.com/AlbercoinDev/Umbrel-AppStore-Albercoin),
en la carpeta `albercoin-store-umbrel-tunnel/`.

Umbrel solo muestra las apps cuyo `id` empieza por el `id` de la tienda. La
tienda usa `id: albercoin-store`, así que la app debe llamarse
`albercoin-store-umbrel-tunnel` y la carpeta de la tienda debe coincidir con ese
ID. El manifiesto y el Compose de este repositorio se copian a la tienda al
publicar.

Para actualizar la tienda:

1. Cambia el código y publica la imagen multiarquitectura desde este repositorio.
2. Fija etiqueta y digest en `umbrel-tunnel/docker-compose.yml`.
3. Copia `umbrel-app.yml` y `docker-compose.yml` a
   `albercoin-store-umbrel-tunnel/` en la tienda.
4. Sube la tienda a `master` y espera a que Umbrel refresque el catálogo.

## Release del VPS

1. Actualiza `vps/VERSION` (debe coincidir con el tag sin la `v`).
2. `cd vps && make dist` genera los binarios, los tarballs, los sidecars
   `.sha256` y `SHA256SUMS`.
3. Crea y sube el tag `vX.Y.Z`. El workflow `vps-release.yml` compila, comprueba
   que el tag coincide con `VERSION` y publica como assets `install.sh`, los
   binarios sueltos, sus `.sha256`, los tarballs y `SHA256SUMS`.
4. El instalador de una línea usa
   `--binary-base https://github.com/AlbercoinDev/umbrel-tunnel/releases/latest/download`,
   que resuelve `umbrel-tunnel-linux-$ARCH`.
5. `umbrel-tunnel update` resuelve por sí solo `releases/latest/download/umbrel-tunnel-linux-$ARCH`,
   usa el sidecar `.sha256` y actualiza también las unidades embebidas (`internal/units`).

## Convenciones

- Código y nombres de API en inglés; textos de UI en `i18n/*.json`.
- Errores de API con `{code, error}` y, si aplica, `detail`.
- Secretos con permisos `600`; escritura atómica.
- No ejecutar nunca `exports.sh` ni comandos de otras apps.
- No montar el socket de Docker.
- Cualquier nueva directiva de WireGuard debe añadirse a la allowlist de
  `wireguard.py` y a sus tests.
