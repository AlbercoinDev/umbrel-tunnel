# Cambios

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
