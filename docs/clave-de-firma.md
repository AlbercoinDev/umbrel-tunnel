# Manual de la clave de firma de releases

Este documento explica cómo se usa la clave Ed25519 que firma las releases de
umbrel-tunnel, cómo guardarla, cómo restaurarla en otra máquina y cómo
sustituirla sin dejar a los usuarios sin actualizaciones.

Aplica a la versión 1.6.8 y posteriores.

## 1. Qué es y por qué importa

Cada release publica `SHA256SUMS` y su firma `SHA256SUMS.sig`. El binario del
VPS y el instalador verifican esa firma antes de instalar o ejecutar nada. La
clave privada es la **raíz de confianza de las actualizaciones**:

- Con ella se firman las releases nuevas.
- La clave pública va embebida en el binario, en `install.sh` y en la app.
- Si se pierde, no se pueden firmar releases que las instalaciones existentes
  acepten.
- Si se filtra, un atacante podría firmar una release maliciosa que pasaría la
  verificación.

No se puede “regenerar la misma clave”: una clave nueva es una identidad nueva.

## 2. Inventario

| Elemento | Ubicación | Permisos |
| --- | --- | --- |
| Clave privada de trabajo | `~/.config/umbrel-tunnel/release-signing.key` | `0600`, directorio `0700` |
| Clave pública del repo | `vps/release-signing.pub.pem` | `0644` |
| Copia embebida en Go | `vps/internal/update/release-signing.pub.pem` | `0644` |
| Clave embebida en el instalador | `vps/install.sh` → `RELEASE_PUBKEY` | — |
| Copia del instalador en la app | `umbrel-tunnel/gateway/install.sh` | `0755` |
| Huella mostrada en la app | `umbrel-tunnel/gateway/app.py` → `RELEASE_SIGNING_FINGERPRINT` | — |
| Secreto de GitHub | `VPS_RELEASE_SIGNING_KEY` | solo lo lee el workflow |
| Firma | `vps/dist/SHA256SUMS.sig`, publicada en la release | — |

Huella actual de la clave pública:

```text
SHA256 23AC5BD6BC78F5E37F733730A70CADB256E0A04FF892F3C53E67F43CE22766BD
```

La huella es el SHA-256 del DER SPKI de la clave pública. No es secreta y se
muestra en **Diagnóstico** y en el paso de instalación del VPS.

## 3. Reglas de custodia

1. La clave privada **nunca** se sube a GitHub, se pega en un chat, se envía por
   correo ni se guarda en una nube sin cifrar.
2. Solo vive en la máquina de publicación (`0600`) y en copias offline
   cifradas.
3. Mantén **dos copias offline** en lugares distintos (USB cifrado, gestor de
   secretos con adjuntos cifrados).
4. La passphrase del archivo cifrado no se guarda junto al archivo.
5. Una sola persona debe poder firmar. Si hay más, usa un gestor de secretos con
   registro de accesos, no copias informales.
6. No crees tags ni releases desde una máquina que no sea de confianza: el
   workflow necesita el secreto.

## 4. Uso diario: publicar una release

El firmado lo hace el workflow; no se firma a mano en local.

1. Cambia la versión en todos los sitios que correspondan (`app.py`,
   `vps/VERSION`, manifiestos, Compose, README).
2. Ejecuta las pruebas (`python -m unittest`, `go test ./...`).
3. Haz commit y push a `main`.
4. Crea y sube el tag:
   ```sh
   git tag -a v1.6.9 -m "Umbrel Tunnel 1.6.9"
   git push origin v1.6.9
   ```
5. El workflow **VPS release**:
   - comprueba que el tag coincide con `vps/VERSION`;
   - compila y genera `SHA256SUMS`;
   - escribe la clave del secreto en `$RUNNER_TEMP` con `0600`;
   - firma con `openssl pkeyutl -sign -rawin`;
   - borra la clave temporal;
   - publica `SHA256SUMS.sig` y la clave pública.
6. Comprueba la release:
   ```sh
   gh release view v1.6.9 --json assets --jq '[.assets[].name]'
   ```
7. Fija el digest de la imagen del gateway en Compose y actualiza la tienda.

Si el secreto no existe, el paso de firma falla y la release no se publica.
Es intencionado.

### Firma manual de prueba (sin publicar)

Para comprobar que la clave de una máquina funciona:

```sh
printf 'prueba\n' > /tmp/ut-test.txt
openssl pkeyutl -sign -rawin \
  -inkey ~/.config/umbrel-tunnel/release-signing.key \
  -in /tmp/ut-test.txt -out /tmp/ut-test.sig
openssl pkeyutl -verify -pubin \
  -inkey vps/release-signing.pub.pem -rawin \
  -in /tmp/ut-test.txt -sigfile /tmp/ut-test.sig
rm -f /tmp/ut-test.txt /tmp/ut-test.sig
```

Debe responder `Signature Verified Successfully`. No publica nada.

## 5. Verificación de una release

```sh
base=https://github.com/AlbercoinDev/umbrel-tunnel/releases/download/v1.6.9
curl -fsSL "$base/SHA256SUMS" -o /tmp/SHA256SUMS
curl -fsSL "$base/SHA256SUMS.sig" -o /tmp/SHA256SUMS.sig
openssl pkeyutl -verify -pubin \
  -inkey vps/release-signing.pub.pem -rawin \
  -in /tmp/SHA256SUMS -sigfile /tmp/SHA256SUMS.sig
```

Y, si quieres comprobar el binario:

```sh
cd /tmp && curl -fsSL "$base/umbrel-tunnel-linux-amd64" -o umbrel-tunnel-linux-amd64
sha256sum -c <(grep 'umbrel-tunnel-linux-amd64$' /tmp/SHA256SUMS)
```

## 6. Copia de seguridad

El repositorio no contiene la clave privada. La copia debe hacerse a mano:

```sh
umask 077
cp ~/.config/umbrel-tunnel/release-signing.key /media/usb-cifrado/
cp vps/release-signing.pub.pem /media/usb-cifrado/
cd /media/usb-cifrado
sha256sum release-signing.key release-signing.pub.pem > SHA256SUMS
sha256sum -c SHA256SUMS
```

Comprueba la huella en el medio:

```sh
openssl pkey -pubin -in release-signing.pub.pem -outform DER \
  | sha256sum | awk '{print toupper($1)}'
```

Debe coincidir con la del apartado 2.

## 7. Restaurar en otra máquina (cambio de equipo)

Situación: la máquina de publicación se sustituye, pero la clave sigue siendo
la misma.

### Antes de tocar nada

- Ten acceso al repositorio y `gh` autenticado (`gh auth status`).
- Ten la copia offline y su passphrase.
- No borres la clave de la máquina antigua hasta terminar.

### Pasos

1. Verifica la copia offline:
   ```sh
   cd /media/usb-cifrado
   sha256sum -c SHA256SUMS
   openssl pkey -pubin -in release-signing.pub.pem -outform DER \
     | sha256sum | awk '{print toupper($1)}'
   ```

2. Instala `openssl` y `gh` en la máquina nueva.

3. Copia la clave a su ruta, con permisos estrictos:
   ```sh
   install -d -m 700 ~/.config/umbrel-tunnel
   install -m 600 release-signing.key ~/.config/umbrel-tunnel/release-signing.key
   ```

4. Comprueba que la clave privada corresponde a la pública publicada:
   ```sh
   openssl pkey -in ~/.config/umbrel-tunnel/release-signing.key \
     -pubout -outform DER | sha256sum | awk '{print toupper($1)}'
   openssl pkey -pubin -in release-signing.pub.pem \
     -outform DER | sha256sum | awk '{print toupper($1)}'
   ```
   Los dos valores deben coincidir con la huella del apartado 2.

5. Firma una prueba como en el apartado 4 y verifica con
   `vps/release-signing.pub.pem`.

6. Actualiza el secreto de GitHub desde la máquina nueva:
   ```sh
   gh secret set VPS_RELEASE_SIGNING_KEY \
     < ~/.config/umbrel-tunnel/release-signing.key
   gh secret list | grep VPS_RELEASE_SIGNING_KEY
   ```

7. Lanza una release de prueba o espera a la siguiente. Comprueba que el
   workflow firma y que la firma verifica:
   ```sh
   gh run list --workflow vps-release.yml --limit 1
   ```

8. Cuando la nueva máquina esté validada, elimina la clave de la antigua:
   ```sh
   rm -f ~/.config/umbrel-tunnel/release-signing.key
   ```
   Si la máquina antigua era compartida o no confiable, no basta con borrar:
   rota la clave (apartado 8) y revisa accesos.

### Qué no cambia

- No hay que tocar datos, emparejamientos ni el VPS.
- No hay que cambiar la clave pública del repo ni la huella.
- Las releases anteriores siguen siendo válidas.

## 8. Sustituir la clave (rotación planificada)

Situación: quieres una clave nueva por política, cambio de responsable o
porque la anterior ya no se considera segura, pero **aún puedes firmar** con
la antigua.

Advertencia: las instalaciones existentes llevan embebida la clave pública
antigua. Si publicas una release firmada solo con la nueva, `umbrel-tunnel
update` la rechazará. La rotación necesita una **release de transición**.

### Fase 1: preparar la clave nueva

1. Genera la clave nueva **en la máquina de publicación**:
   ```sh
   umask 077
   openssl genpkey -algorithm ED25519 \
     -out ~/.config/umbrel-tunnel/release-signing-next.key
   openssl pkey -in ~/.config/umbrel-tunnel/release-signing-next.key \
     -pubout -out vps/release-signing-next.pub.pem
   ```
2. Calcula su huella:
   ```sh
   openssl pkey -pubin -in vps/release-signing-next.pub.pem -outform DER \
     | sha256sum | awk '{print toupper($1)}'
   ```
3. Guarda una copia offline de la clave nueva (apartado 6).

### Fase 2: código que acepta ambas claves

En la release de transición, la verificación debe aceptar la clave antigua y la
nueva:

- `vps/internal/update/`: embeber también
  `release-signing-next.pub.pem` y aceptar si verifica cualquiera de las dos.
- `vps/install.sh`: añadir `RELEASE_PUBKEY_NEXT` y probar ambas en
  `verify_download`.
- Copiar `vps/install.sh` a `umbrel-tunnel/gateway/install.sh`.
- Actualizar `RELEASE_SIGNING_FINGERPRINT` o añadir la huella nueva a la UI.
- Añadir pruebas: firma con antigua válida, firma con nueva válida, firma con
  una tercera clave rechazada.
- Mantener la clave antigua como principal durante esta fase.

### Fase 3: publicar la transición firmada con la clave antigua

1. Sube el código y crea el tag. El secreto de GitHub sigue siendo la clave
   **antigua**.
2. Verifica que la release está firmada con la antigua y que el binario nuevo
   acepta ambas.
3. Los usuarios actualizan a esta versión mediante el mecanismo actual.

### Fase 4: cambiar el secreto a la clave nueva

1. Cambia el secreto:
   ```sh
   gh secret set VPS_RELEASE_SIGNING_KEY \
     < ~/.config/umbrel-tunnel/release-signing-next.key
   ```
2. Mueve la clave nueva a la ruta de trabajo y conserva la antigua hasta la
   fase 5:
   ```sh
   cd ~/.config/umbrel-tunnel
   mv release-signing.key release-signing.old.key
   mv release-signing-next.key release-signing.key
   chmod 600 release-signing.key release-signing.old.key
   ```
3. Publica la siguiente release. Debe quedar firmada con la nueva.
4. Verifica la firma con **ambas** claves públicas:
   - con la nueva debe verificar;
   - con la antigua debe fallar.

### Fase 5: retirar la clave antigua

1. Espera una ventana de gracia (por ejemplo, dos releases o 90 días) para que
   las instalaciones actualicen.
2. Elimina la clave antigua del código y del instalador:
   - `vps/release-signing.pub.pem` → clave nueva;
   - `vps/internal/update/release-signing.pub.pem` → clave nueva;
   - `RELEASE_PUBKEY` del instalador → clave nueva;
   - quitar la aceptación de la clave antigua;
   - actualizar huellas y documentación.
3. Publica una release firmada con la nueva que ya no acepte la antigua.
4. Destruye la clave antigua de todas las copias offline.
5. Revoca accesos de la máquina o persona que la tenía.

## 9. Rotación de emergencia

### Caso A: la clave se ha perdido y no puedes firmar

No hay release de transición posible. Las instalaciones existentes rechazarán
cualquier release nueva.

1. Genera una clave nueva (apartado 8, fase 1).
2. Actualiza el código, el instalador y la huella a la clave nueva.
3. Publica una release con la clave nueva. El workflow firmará, pero las
   instalaciones antiguas no la aceptarán automáticamente.
4. Avisa en las notas de la release: hay que **ejecutar el instalador a mano**
   una vez:
   ```sh
   curl -fsSL https://raw.githubusercontent.com/AlbercoinDev/umbrel-tunnel/vX.Y.Z/vps/install.sh \
     | sudo bash -s -- --endpoint TU_IP --token TU_TOKEN ...
   ```
   El instalador nuevo lleva la clave nueva embebida y verifica la release
   nueva; después, `umbrel-tunnel update` vuelve a funcionar.
5. Verifica en un VPS desechable antes de anunciarlo.

### Caso B: la clave se ha filtrado o sospechas que está comprometida

Además de lo anterior:

1. Asume que pueden existir releases firmadas maliciosas. Publica un aviso
   inmediato en el repositorio y en las notas.
2. Rota a una clave nueva cuanto antes.
3. Pide a los usuarios que comparen la huella que muestra la app con la huella
   publicada y que actualicen solo desde el repositorio oficial.
4. Revisa accesos de GitHub, secretos y máquinas. Cambia contraseñas y tokens.
5. Si el atacante también controla GitHub, la firma no basta: hay que recuperar
   la cuenta, revisar releases y assets, y comunicar el incidente.

No existe revocación remota de una clave embebida: la única salida es una
instalación manual con la clave nueva.

## 10. Errores comunes

| Síntoma | Causa probable | Solución |
| --- | --- | --- |
| `falta el secreto VPS_RELEASE_SIGNING_KEY` | Secreto no configurado | `gh secret set ...` |
| `firma de release inválida` | Clave distinta, PEM con saltos alterados o tag equivocado | Verifica huella y vuelve a subir el secreto |
| `la release no trae SHA256SUMS.sig` | Workflow antiguo o release no firmada | Revisa el tag; no publiques sin firma |
| `checksum del binario instalado no coincide` | Binario modificado o release manipulada | Reinstala desde la release oficial y revisa el VPS |
| `openssl: command not found` | Falta openssl | `apt install openssl` / `apk add openssl` |
| La clave no firma pero el archivo existe | Permisos o formato incorrecto | `chmod 600`, comprueba `openssl pkey -in ... -noout` |
| `update` rechaza una release nueva | Clave rotada sin transición | Sigue el apartado 8; o instalador manual en emergencia |

## 11. Lista de comprobación

Antes de publicar:

- [ ] `vps/VERSION`, `RELEASE_VERSION` y manifiestos coinciden.
- [ ] Pruebas Go y Python en verde.
- [ ] Secreto `VPS_RELEASE_SIGNING_KEY` presente.
- [ ] Tag creado y subido.
- [ ] Workflow de release en verde.
- [ ] `SHA256SUMS.sig` descargada y verificada.
- [ ] Huella de la app coincide con la pública.
- [ ] Digest de la imagen fijado y tienda actualizada.

Antes de rotar:

- [ ] Copia offline verificada de la clave antigua y de la nueva.
- [ ] Release de transición publicada y validada.
- [ ] Usuarios con margen para actualizar.
- [ ] Ventana de gracia definida.
- [ ] Plan de comunicación y rollback.

## 12. Referencias

- `.github/workflows/vps-release.yml`: firma en CI.
- `vps/release-signing.pub.pem`: clave pública canónica.
- `vps/install.sh`: verificación del instalador.
- `vps/internal/update/sign.go`: verificación en el binario.
- `umbrel-tunnel/gateway/app.py`: huella mostrada en la app.
- `docs/seguridad.md`: plan de TLS local (apartado C).
