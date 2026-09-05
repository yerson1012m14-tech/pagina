# XITFORGE · Keys gratis con Linkvertise

Integración preparada para jasonxitoficial.com y el servidor de licencias existente en Render. No se ha publicado ni se han cambiado las variables de Render. La entrega permanece deshabilitada hasta configurar el enlace y la verificación de tu cuenta.

Las keys duran **3 horas desde el primer uso en XITFORGE**. El siguiente reclamo se permite **24 horas después de recibir la key**. Los anuncios se completan en Linkvertise y el regreso se verifica desde el servidor antes de crear una licencia real. No se exigen redes sociales ni se añaden otros proveedores.

## Archivos

| Archivo del ZIP | Destino |
| --- | --- |
| `pagina/index.html` | Repositorio `yerson1012m14-tech/pagina`, reemplazando el HTML público cuando quieras publicar esta versión. Conserva la carpeta `ipas/`. |
| `XITFORGE-License-Server/server.js` | Raíz del repositorio `yerson1012m14-tech/XITFORGE-License-Server`. |
| `XITFORGE-License-Server/free-key-routes.js` | La misma carpeta que `server.js`. |
| `XITFORGE-License-Server/server.patch` | Diferencias para revisar o integrar sobre el servidor actual. |
| `XITFORGE-License-Server/test-free-keys.cjs` | Pruebas opcionales para desarrollo. No hacen falta para arrancar el servicio. |

El `server.js` preparado parte del blob de GitHub `51d1d04a776469bb0d001976b5a111ae78f8b912`. Si modificas el servidor después de esta entrega, integra `server.patch` sobre tus cambios. El parche añade una duración en segundos y conserva la duración en días de las licencias existentes. El panel `public/index.html`, `options-routes.js` y las IPA no se reemplazan.

## Conectar la cuenta y activar

1. Publica primero los dos archivos del servidor y el HTML público. Deja `FREE_KEYS_ENABLED=false`. Se usa el mismo servicio de Render y la misma base PostgreSQL; no hace falta otro servidor ni tener tu PC encendida.
2. Comprueba que `https://xitforge-license-server.onrender.com/api/free-key/config` devuelve `ok: true` y `enabled: false`.
3. Crea en tu cuenta de Linkvertise un enlace de destino (**Target-Link**). Usa exactamente este destino:

   `https://xitforge-license-server.onrender.com/free-key/return`

4. Copia el enlace de Linkvertise que se genera. En **Environment** del servicio de licencias de Render, configura estas variables:

| Variable | Valor |
| --- | --- |
| `LINKVERTISE_URL` | Tu enlace completo, por ejemplo el formato `https://linkvertise.com/ID/nombre`. No pongas solo `linkvertise.com`. |
| `LINKVERTISE_ANTI_BYPASS_TOKEN` | El token privado de 64 caracteres de Anti-Bypassing de tu cuenta. Introdúcelo únicamente en Render; no lo pongas en el HTML, GitHub ni en el chat. |
| `FREE_KEYS_ENABLED` | `false` durante la preparación; `true` al terminar la configuración. |

5. Configura Anti-Bypassing en Linkvertise después de preparar el backend. Este ajuste afecta a todos los enlaces de la cuenta: sus destinos también deben admitir la verificación. La [documentación oficial](https://publisher.linkvertise.com/documentations/Anti_Bypass_Documentation.pdf) especifica que funciona con Target-Links y que el hash de regreso dura 10 segundos y se utiliza una vez.
6. Cambia `FREE_KEYS_ENABLED` a `true` en Render. Tras el despliegue, el endpoint de configuración debe indicar `enabled: true`. Entonces el botón de la ventana llevará a tu Linkvertise y el regreso abrirá la misma ventana con la key y su botón para copiar.

No compartas el destino de regreso como si fuera el enlace para ver anuncios: el visitante debe empezar desde el botón de la página para crear su sesión. Un regreso sin verificación válida no entrega una key.

## Comportamiento y límites

- La espera se guarda en PostgreSQL y se comprueba por navegador y conexión pública. Borrar las cookies no permite repetir el reclamo desde la misma conexión; personas que comparten una conexión pueden compartir el límite. No es una identificación personal ni el identificador del iPhone: cambiar ambos, navegador e IP, no puede distinguirse de un nuevo visitante sin añadir autenticación.
- Cada key tiene el límite existente de un dispositivo. Una nueva petición o recarga recupera la misma entrega durante las 24 horas, sin generar otra key. Las licencias gratuitas aparecen en la tabla habitual con una nota que indica las 3 horas.
- La key recuperable se guarda cifrada durante el período de reclamo. La URL de regreso contiene un comprobante firmado en el fragmento; el HTML lo retira de la barra de direcciones y lo guarda solo en la sesión del navegador.
- `FREE_KEYS_SECRET` es opcional; si no se define se usa el secreto administrativo existente, con claves derivadas separadas. Mantén ese secreto estable para conservar las identidades y los comprobantes de reclamo.
- Si Linkvertise rechaza la verificación o no responde, no se crea la key ni se inicia la espera. Su límite de 10 segundos requiere que el servidor responda a tiempo; una instancia de Render que se esté despertando puede obligar a repetir el intento.

## Validación realizada

Se ejecutaron 4 pruebas con Node 24, Express 5.2.1 y el motor PostgreSQL de PGlite 0.5.8. Incluyen respuestas falsas de Linkvertise, comprobantes alterados o vencidos, solicitudes sin sesión, creación solo tras verificación positiva, repetición del regreso, dos intentos desde una conexión compartida, espera de 24 horas, inicio exacto de las 3 horas y conservación de licencias de 7 días. Se comprobó además la sintaxis y que el HTML mantiene el diseño, el menú, la ventana del video y las descargas.

La respuesta de Linkvertise fue simulada en estas pruebas; faltan el enlace y el token de tu cuenta para verificar el recorrido real. PGlite usa una conexión; no se hizo una prueba de carga con varios procesos de PostgreSQL. No se realizó una prueba visual en navegador.

Para repetir las pruebas en una copia de desarrollo del repositorio, instala `@electric-sql/pglite@0.5.8` como dependencia de desarrollo y ejecuta `node --test test-free-keys.cjs`. No es una dependencia necesaria en Render.
