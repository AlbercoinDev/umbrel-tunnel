# Plan de seguridad: TLS en Umbrel (apartado C)

Estado: **aparcado**. Este documento describe el diseño acordado para que el
VPS deje de terminar TLS y lo haga el propio Umbrel, de modo que el proveedor
del VPS nunca vea tráfico HTTP en claro ni guarde certificados.

No hay código de este plan en la versión actual (1.6.8). El modo por defecto
sigue siendo el actual: **TLS termina en el VPS**.

## 1. Situación actual

```
Internet ──► VPS :80/:443 ──► termina TLS (autocert) ──► wg0 ──► HAProxy :20000 ──► app
             nftables DNAT        certificados en el VPS       Umbrel
```

- `vps/internal/edge/edge.go` obtiene certificados con `autocert` (HTTP-01) y
  termina HTTPS y TLS de TCP.
- El VPS necesita `CAP_NET_BIND_SERVICE` para escuchar en 80/443.
- Los certificados y sus claves viven en el VPS.
- La app de Umbrel solo hace proxy TCP/UDP local; no ve TLS.

Consecuencia: el VPS (y su proveedor) puede ver HTTP en claro después de
deshacer TLS y tiene las claves privadas.

## 2. Objetivo

Mover la terminación TLS al Umbrel sin romper publicaciones, certificados ni
emparejamientos:

```
Internet ──► VPS :80/:443 ──► L4 (sin descifrar) ──► wg0 ──► HAProxy Umbrel
             DNAT                    túnel                 termina TLS
                                                           certificados en data/
```

- El VPS solo reenvía bytes.
- Las claves de los certificados no salen del Umbrel.
- Se mantiene el modo actual por peer (`edge_mode`) para no forzar migraciones.

## 3. Alcance recomendado (C1)

Primera entrega, deliberadamente limitada:

- `edge_mode: local` disponible y **por defecto solo en instalaciones nuevas**.
- **HTTP/HTTPS** terminados en Umbrel.
- **Un Umbrel por VPS**.
- TLS de TCP no HTTP (Electrs 50002, etc.) en una fase posterior.
- VPS compartido con SNI/Host routing en una fase posterior.

C2 (migración guiada) y C3 (VPS compartido + TCP/TLS) quedan documentados pero
no forman parte de C1.

## 4. Diseño técnico

### 4.1 Modelo de datos

Añadir a cada peer del VPS:

```json
{ "edge_mode": "vps" }   // actual
{ "edge_mode": "local" } // TLS en el Umbrel
```

- Valor por defecto: `vps`.
- Instalaciones nuevas creadas con 1.7.x: `local` si el usuario lo elige o si
  es el valor por defecto acordado.
- Se expone en la API de peers (`GET/PUT /api/peers/{id}`) y en la app.

En la app, `config.json` guarda el dominio base y las publicaciones ya
existentes; no hace falta migrar el formato.

### 4.2 Puertos y capacidades

No añadir `CAP_NET_BIND_SERVICE` al gateway. Se usan puertos altos dentro del
túnel:

| Público en VPS | Destino en Umbrel |
| --- | --- |
| 80/tcp (ACME y redirección) | 10.0.0.2:8080 |
| 443/tcp | 10.0.0.2:8443 |
| Puerto TLS de TCP (p. ej. 50002) | 10.0.0.2:25002 |

El VPS cambia su DNAT según `edge_mode`; HAProxy escucha en puertos no
privilegiados y no hacen falta capacidades nuevas.

### 4.3 HAProxy en Umbrel

- `frontend` HTTP en 8080: sirve tokens ACME y redirige a HTTPS.
- `frontend` HTTPS en 8443: elige certificado por SNI y reenvía al destino.
- `frontend` por cada publicación TLS de TCP: elige certificado por SNI y
  reenvía al puerto interno real (por ejemplo 50001).
- Los certificados se cargan desde `/run/umbrel-tunnel/tls/` (tmpfs) con `0600`;
  nunca se escriben en claro en `${APP_DATA_DIR}`.

### 4.4 Certificados y ACME

- Almacén persistente: `data/tls/`, cifrado con `vault` (AES-256-GCM), igual
  que `config.json`.
- Al arrancar: se descifran a `/run/umbrel-tunnel/tls/` y se recarga HAProxy.
- Emisión y renovación con **lego** (binario estático) frente a implementar
  ACME en Python:
  - HTTP-01 contra el puerto 8080 del túnel.
  - Estado de cuenta y certificados en `data/tls/`, cifrados después de cada
    operación.
  - Reintentos con backoff y *staging* de Let's Encrypt para pruebas.
- Un certificado por nombre publicado, como ahora; sin certificado wildcard.

### 4.5 VPS

- `edge.go` sigue existiendo para `edge_mode: vps`.
- Para `local`, el peer no usa `autocert`; su DNAT apunta a 8080/8443/25002.
- Los certificados del VPS se conservan hasta que el usuario confirme el cambio
  (rollback inmediato).

### 4.6 VPS compartido (C3)

Un solo 80/443 público debe repartirse entre peers:

- 443: HAProxy en modo TCP inspecciona SNI (`req_ssl_sni`) y elige el peer.
  El VPS ve el nombre del dominio, no el contenido.
- 80: inspección del `Host` en claro para ACME y redirección; solo se ven tokens
  ACME.
- Cada peer mantiene sus propios certificados y termina TLS.

Esto se implementará solo después de estabilizar C1 en un VPS de un único
Umbrel.

## 5. Migración (C2)

Por peer y por dominio, nunca automática:

1. Mantener el edge del VPS activo.
2. Emitir el certificado en Umbrel con *staging* y comprobar la cadena.
3. Emitir en producción y verificar.
4. Cambiar `edge_mode` a `local` (corte breve por dominio).
5. Comprobar HTTPS y TCP/TLS.
6. Pasado un periodo de gracia, borrar los certificados del VPS.

Rollback: volver a `edge_mode: vps`; los certificados antiguos siguen en el VPS
hasta el paso 6.

## 6. Pruebas y criterios de aceptación

- Unitarias: selección de certificado por SNI, render de HAProxy, cifrado y
  descifrado de certificados, DNAT por `edge_mode`.
- Integración con **pebble** (ACME de prueba): emisión, renovación y fallo de
  validación.
- VPS desechable: instalación nueva en `local`, publicación HTTP/HTTPS, corte y
  rollback a `vps`.
- Seguridad: el VPS no abre TLS, no guarda claves y no puede descifrar; el
  gateway no gana capacidades nuevas.
- Compatibilidad: un peer en `vps` y otro en `local` conviven sin interferirse
  (aunque el routing compartido sea C3).

Criterio de aceptación de C1:

- Una instalación nueva publica un servicio HTTPS sin que el VPS tenga el
  certificado ni pueda ver el tráfico.
- Renovación automática comprobada.
- El modo `vps` sigue funcionando sin cambios para instalaciones existentes.

## 7. Riesgos

| Riesgo | Mitigación |
| --- | --- |
| Límites de Let's Encrypt al reemitir | Staging primero; por dominio; ventana de gracia |
| Corte de servicio al conmutar | Rollback a `vps` inmediato |
| Pérdida de certificados en restauración | `data/tls` cifrado viaja en la copia; descifrar al arrancar |
| Bug en HAProxy deja sin HTTPS | Validar configuración candidata antes de recargar, como ya hace `proxy.py` |
| VPS compartido mal enrutado | C3 separado, con pruebas por SNI/Host |
| Puertos 80/443 ocupados en Umbrel | Son puertos internos del contenedor y del túnel; no se publican en el host |

## 8. Estimación

| Fase | Trabajo | Estimación |
| --- | --- | --- |
| C1 | lego + almacén cifrado + HAProxy HTTP/HTTPS + `edge_mode` + DNAT + pruebas | 3–5 días |
| C2 | Migración guiada, staging, rollback, documentación | 2–3 días |
| C3 | SNI/Host multi-peer + TLS de TCP no HTTP | 5–10 días |

## 9. Decisiones pendientes

1. Confirmar C1 como alcance inicial (recomendado).
2. Confirmar `local` como valor por defecto solo en instalaciones nuevas.
3. Confirmar **lego** frente a una implementación ACME en Python.
4. Confirmar que el TLS de TCP no HTTP y el VPS compartido quedan para C3.

## 10. Fuera de alcance

- DNS management o cambios en el proveedor de DNS.
- Certificados wildcard.
- Sustituir WireGuard o el modelo de emparejamiento.
- Cambiar el modo `vps` de instalaciones existentes sin su confirmación.

## 11. Referencias

- `vps/internal/edge/edge.go`: terminación TLS actual en el VPS.
- `umbrel-tunnel/gateway/proxy.py`: HAProxy local.
- `umbrel-tunnel/gateway/vault.py`: cifrado en reposo.
- `docs/TLS.md`: dominios, ACME y TLS TCP actuales.
- `docs/SECURITY.md`: modelo de confianza.
