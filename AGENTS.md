# Repository guidance

## Boundaries and entrypoints
- Two independently deployed halves: `vps/` is a Go module (CLI/daemon at `cmd/umbrel-tunnel`); `umbrel-tunnel/gateway/` is a flat Python app, not an installable package. Run their commands from the respective directories.
- Start the gateway with `python3 serve.py`, not `flask run`: it calls startup and launches background reconciliation before serving with Waitress. `app.py` owns HTTP routes; `sync.py` reconciles publications; `vps.py` is the remote API client.
- TCP uses local HAProxy, UDP uses `udp.py`; HTTPS/TLS termination lives on the VPS in `internal/edge`. The VPS daemon owns mutable peer/forward state; CLI mutations go through its authenticated API rather than independently rewriting JSON.

## Verification
- Use Go **1.26.0** as declared in `vps/go.mod`.
- From `vps/`: `gofmt -l .`, `go vet ./...`, `go test ./...`, then `CGO_ENABLED=0 go build -trimpath -o /tmp/opencode/umbrel-tunnel ./cmd/umbrel-tunnel`. CI rejects any output from `gofmt -l .`; `make check` instead formats files in place before vet/tests.
- Focused Go test: `go test ./internal/httpapi -run '^TestName$' -count=1` (substitute the actual package/test).
- Gateway dependencies: `python3 -m pip install flask pyyaml waitress` inside a virtualenv; CI uses Python 3.12. No requirements file or Python build manifest exists.
- From `umbrel-tunnel/gateway/`: `python3 -m py_compile *.py` and `python3 -m unittest discover -s tests -v`.
- Focused gateway tests: `python3 -m unittest discover -s tests -p 'test_publications.py' -v`; add `-k substring` to filter test names. Tests redirect state/config to temporary directories and mock host operations; passing them does not verify real WireGuard/HAProxy or Umbrel deployment.
- Local UI: `UMBREL_TUNNEL_DEV=1 UMBREL_TUNNEL_DATA=/tmp/opencode/tunnel-data UMBREL_APP_DATA=/tmp/opencode/app-data PORT=8081 python3 serve.py` (gateway directory). Password is `dev`; never enable dev mode in production. This is not a functional tunnel setup by itself.

## Packaging and releases
- When adding gateway Python modules, update the explicit `COPY` list in `gateway/Dockerfile` and the compile list in `.github/workflows/ci.yml`; a local import succeeding does not mean the module ships in the image.
- From `vps/`, `make dist` deletes/rebuilds `dist/`, cross-compiles static Linux amd64/arm64 binaries, and produces tarballs/checksums. Plain cross-compile targets have no source prerequisites and can reuse stale binaries; prefer `make dist` for release artifacts.
- Edit system integration sources in `vps/internal/units/files/`, not generated `dist/**/packaging/`. Units are embedded in the Go binary and copied into release tarballs.
- Every `v*` tag triggers **both** VPS release and gateway multi-architecture image publication. The VPS workflow requires the tag without `v` to equal `vps/VERSION`.
- Umbrel Compose downloads a published image; it does not build local gateway changes. Pin both tag and multi-architecture index digest in `umbrel-tunnel/docker-compose.yml` after publishing.
- The actual Community App Store is the separate `AlbercoinDev/Umbrel-AppStore-Albercoin` repository. Copy this repo's manifest/Compose there under `albercoin-store-umbrel-tunnel/`; keep that app ID, `APP_HOST=albercoin-store-umbrel-tunnel_gateway_1`, internal port 8081, and manifest port 8642 aligned (CI checks them).

## Constraints to preserve
- Discovery parses other apps' `exports.sh`, `.env`, and Compose as data only: never source or execute them, and do not add a Docker socket mount.
- WireGuard configuration is structured/allowlisted in `gateway/wireguard.py`; new directives need validation and tests, not arbitrary config passthrough. Pairing codes must not transport private keys; their API URL must stay within the tunnel subnet.
- Keep the VPS API tunnel-only by default and public port 22 reserved for VPS SSH. Installer/deployment commands modify host networking and systemd; use unit tests for ordinary verification, not a live install.
- Gateway UI strings live in `gateway/i18n/es.json` and `en.json`; update both catalogs together (tests enforce identical keys).
- For publication ownership/conflicts and applied-vs-reachable status, consult `docs/PUBLICATIONS.md`; for certificate/routing changes, `docs/TLS.md`; for deployment privileges, `docs/SECURITY.md`.
