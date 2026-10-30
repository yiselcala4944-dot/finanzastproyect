# Confinanzas – sitio web con panel de administrador

## Acceso de administrador (fijo)
- Dirección: `https://TU-DOMINIO/admin`
- Usuario: `admin.confinanzas`
- Contraseña: `Cf-Chucuri#2026!Kx9`

No existe ninguna pantalla para crear o cambiar estos datos. Solo se cambian editando
las dos líneas `ADMIN_USER` y `ADMIN_PASS` al inicio de `server.js` y reiniciando.

## Cómo ejecutarlo
Requiere Node.js 18 o superior (no necesita instalar nada más).

    node server.js        # abre http://localhost:3000

Variables opcionales: `PORT` (puerto) y `DATA_DIR` (carpeta donde se guardan datos y archivos subidos).

## Qué hace el panel
- **Estados**: foto o video + título + texto, en círculos arriba del sitio (como historias). Duran 24 h, 3 d, 7 d o hasta borrarlos.
- **Novedades**: sección fija del sitio con 6 diseños (foto derecha, izquierda, grande arriba, foto de fondo, solo texto, tarjetas) y botón opcional.
- **Alertas**: ventana emergente al entrar al sitio, con X para cerrarla.
- Cada elemento se puede editar, ocultar o eliminar.

## Importante al publicarlo
- Necesita un hosting que ejecute Node.js (VPS, Render, Railway, etc.), NO sirve un hosting solo de archivos estáticos.
- Los datos y archivos subidos viven en la carpeta `data/`: debe ser un disco persistente y conviene respaldarla.
- Usa HTTPS en producción.
