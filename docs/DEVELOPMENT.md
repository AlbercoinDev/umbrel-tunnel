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
- tarballs con `install.sh`, `VERSION` y `packaging/`
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
publicada. Mientras no exista, `ghcr.io/umbrel-tunnel/umbrel-tunnel-gateway:1.0.0`
es un marcador y la instalación fallará.

1. Crea el repositorio en GitHub y el paquete en GHCR.
2. Autentícate:

   ```bash
   echo "$GITHUB_TOKEN" | docker login ghcr.io -u <OWNER> --password-stdin
   ```

3. Construye y publica `amd64` + `arm64`:

   ```bash
   cd umbrel-tunnel/gateway
   docker buildx build \
     --platform linux/amd64,linux/arm64 \
     -t ghcr.io/<OWNER>/umbrel-tunnel-gateway:1.0.0 \
     --push .
   ```

4. Obtén el digest del índice multi-arquitectura:

   ```bash
   docker buildx imagetools inspect ghcr.io/<OWNER>/umbrel-tunnel-gateway:1.0.0
   ```

5. Fija imagen + digest en `umbrel-tunnel/docker-compose.yml`:

   ```yaml
   image: ghcr.io/<OWNER>/umbrel-tunnel-gateway:1.0.0@sha256:<DIGEST>
   ```

6. Actualiza `repo`, `support`, `website`, `submitter` y `submission` en
   `umbrel-tunnel/umbrel-app.yml` con las URLs reales.

El linter oficial de Umbrel exige que la imagen tenga etiqueta **y** digest.
Hasta que se publique, el linter reporta `image.pinned`; es el único error
esperado.

## Linter de Umbrel

```bash
git clone --depth 1 https://github.com/getumbrel/umbrel-apps /tmp/umbrel-apps
cd /tmp/umbrel-apps
npm install
UMBREL_APP_LINT_ROOT=/ruta/a/este/repositorio \
  node .tools/lint-apps.mjs umbrel-tunnel --format text
```

Avisos esperados y justificados:

- `access.cap_add`: `NET_ADMIN` y `SYS_MODULE` son necesarios para WireGuard.
- `access.host_mount`: `/lib/modules:ro` solo se usa para `modprobe`.
- `access.security_opt`: `no-new-privileges` es una medida de seguridad, no un
  privilegio.

## Community App Store

La raíz del repositorio contiene `umbrel-app-store.yml`:

```yaml
id: "umbrel-tunnel"
name: "Umbrel Tunnel"
```

El ID de la app (`umbrel-tunnel`) debe empezar por el ID de la tienda. Para
publicar:

1. Sube el repositorio a GitHub.
2. En UmbrelOS, añade la URL del repositorio como Community App Store.
3. Instala la app.

La app debe estar en una carpeta con el mismo nombre que su `id`
(`umbrel-tunnel/`).

## Release del VPS

1. Actualiza `vps/VERSION`.
2. `cd vps && make dist`.
3. Publica los tarballs y `SHA256SUMS` como assets del release.
4. El instalador de una línea puede usar
   `--binary https://github.com/<OWNER>/<REPO>/releases/latest/download/umbrel-tunnel-linux-amd64`.

## Convenciones

- Código y nombres de API en inglés; textos de UI en `i18n/*.json`.
- Errores de API con `{code, error}` y, si aplica, `detail`.
- Secretos con permisos `600`; escritura atómica.
- No ejecutar nunca `exports.sh` ni comandos de otras apps.
- No montar el socket de Docker.
- Cualquier nueva directiva de WireGuard debe añadirse a la allowlist de
  `wireguard.py` y a sus tests.
