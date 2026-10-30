'use strict';
/* ==========================================================================
   Servidor de Confinanzas Multiservicios Integrales
   - Sin dependencias: solo necesita Node.js 18 o superior.
   - Sirve el sitio público, el panel /admin y guarda estados, novedades y alertas.
   ========================================================================== */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

/* ------------------------------------------------------------------
   CREDENCIALES DEL ADMINISTRADOR (FIJAS)
   No existe ninguna pantalla para crearlas ni cambiarlas.
   Solo se cambian editando estas dos líneas y reiniciando el servidor.
   ------------------------------------------------------------------ */
const ADMIN_USER = 'admin.confinanzas';
const ADMIN_PASS = 'Cf-Chucuri#2026!Kx9';

const PORT = parseInt(process.env.PORT, 10) || 3000;
const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, 'public');
const DATA_DIR = process.env.DATA_DIR || path.join(ROOT, 'data');
const UPLOADS_DIR = path.join(DATA_DIR, 'uploads');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const MAX_UPLOAD = 150 * 1024 * 1024; // 150 MB por archivo
const SESSION_MS = 8 * 60 * 60 * 1000; // la sesión dura 8 horas
const SECRET = crypto.createHash('sha256').update('cf-sesion|' + ADMIN_USER + '|' + ADMIN_PASS).digest();

const MIME = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8', '.svg': 'image/svg+xml', '.ico': 'image/x-icon',
  '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png', '.webp': 'image/webp', '.gif': 'image/gif',
  '.mp4': 'video/mp4', '.webm': 'video/webm', '.mov': 'video/quicktime', '.m4v': 'video/mp4'
};
const MEDIA_EXT = {
  '.jpg': 'imagen', '.jpeg': 'imagen', '.png': 'imagen', '.webp': 'imagen', '.gif': 'imagen',
  '.mp4': 'video', '.webm': 'video', '.mov': 'video', '.m4v': 'video'
};
const TIPOS = ['estados', 'novedades', 'alertas'];
const LAYOUTS = ['derecha', 'izquierda', 'arriba', 'fondo', 'texto', 'tarjeta'];
const DURACIONES = { '24h': 24 * 3600e3, '3d': 3 * 86400e3, '7d': 7 * 86400e3, siempre: null };

fs.mkdirSync(UPLOADS_DIR, { recursive: true });

/* ---------------------------- Base de datos ---------------------------- */
function leerDB() {
  try {
    const d = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    TIPOS.forEach(t => { if (!Array.isArray(d[t])) d[t] = []; });
    return d;
  } catch (e) {
    return { estados: [], novedades: [], alertas: [] };
  }
}
function guardarDB(d) {
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(d, null, 2));
  fs.renameSync(tmp, DB_FILE);
}
if (!fs.existsSync(DB_FILE)) guardarDB(leerDB());

/* ------------------------------ Utilidades ------------------------------ */
function json(res, code, obj, extra) {
  const body = JSON.stringify(obj);
  res.writeHead(code, Object.assign({
    'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff'
  }, extra || {}));
  res.end(body);
}
function leerCuerpo(req, limite) {
  return new Promise((resolve, reject) => {
    let size = 0; const partes = [];
    req.on('data', c => {
      size += c.length;
      if (size > (limite || 1024 * 1024)) { reject(new Error('grande')); req.destroy(); return; }
      partes.push(c);
    });
    req.on('end', () => {
      try { resolve(partes.length ? JSON.parse(Buffer.concat(partes).toString('utf8')) : {}); }
      catch (e) { reject(new Error('json')); }
    });
    req.on('error', reject);
  });
}
function txt(v, max) { return typeof v === 'string' ? v.trim().slice(0, max) : ''; }
function seguroIgual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

/* ------------------------------- Sesión -------------------------------- */
function firmar(exp) { return crypto.createHmac('sha256', SECRET).update(String(exp)).digest('hex'); }
function crearToken() { const exp = Date.now() + SESSION_MS; return exp + '.' + firmar(exp); }
function cookies(req) {
  const o = {};
  (req.headers.cookie || '').split(';').forEach(p => {
    const i = p.indexOf('='); if (i > 0) o[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return o;
}
function sesionValida(req) {
  const t = cookies(req).cf_admin; if (!t) return false;
  const [exp, sig] = t.split('.');
  if (!exp || !sig || Number(exp) < Date.now()) return false;
  const esperado = firmar(exp);
  return sig.length === esperado.length && crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(esperado));
}
function cookieSesion(req, valor, maxAge) {
  const seguro = req.socket.encrypted || req.headers['x-forwarded-proto'] === 'https';
  return 'cf_admin=' + valor + '; Path=/; HttpOnly; SameSite=Strict; Max-Age=' + maxAge + (seguro ? '; Secure' : '');
}
/* Freno a intentos de contraseña: 6 fallos por IP cada 15 minutos */
const intentos = new Map();
function ipDe(req) { return (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || '?'; }
function bloqueado(ip) {
  const r = intentos.get(ip); if (!r) return 0;
  if (Date.now() > r.hasta) { intentos.delete(ip); return 0; }
  return r.n >= 6 ? Math.ceil((r.hasta - Date.now()) / 60000) : 0;
}
function falloLogin(ip) {
  const r = intentos.get(ip);
  if (!r || Date.now() > r.hasta) intentos.set(ip, { n: 1, hasta: Date.now() + 15 * 60000 });
  else r.n++;
}

/* ------------------------ Archivos subidos (media) ----------------------- */
function mediaValida(m) {
  if (!m || typeof m !== 'object') return null;
  const url = txt(m.url, 200);
  const mm = /^\/uploads\/([a-f0-9]{24}\.[a-z0-9]{3,4})$/.exec(url);
  if (!mm) return null;
  const tipo = MEDIA_EXT[path.extname(mm[1])];
  if (!tipo || !fs.existsSync(path.join(UPLOADS_DIR, mm[1]))) return null;
  return { url, tipo };
}
function borrarMedia(m) {
  if (m && m.url) fs.unlink(path.join(UPLOADS_DIR, path.basename(m.url)), () => {});
}
function limpiarHuerfanos() {
  try {
    const db = leerDB(); const usados = new Set();
    TIPOS.forEach(t => db[t].forEach(i => { if (i.media) usados.add(path.basename(i.media.url)); }));
    fs.readdirSync(UPLOADS_DIR).forEach(f => {
      const p = path.join(UPLOADS_DIR, f);
      if (!usados.has(f) && Date.now() - fs.statSync(p).mtimeMs > 3600e3) fs.unlink(p, () => {});
    });
  } catch (e) { /* nada */ }
}

function subir(req, res, u) {
  const ext = path.extname(u.searchParams.get('name') || '').toLowerCase();
  if (!MEDIA_EXT[ext]) return json(res, 400, { error: 'Formato no permitido. Usa JPG, PNG, WEBP, GIF, MP4, WEBM o MOV.' });
  if (parseInt(req.headers['content-length'] || '0', 10) > MAX_UPLOAD)
    return json(res, 413, { error: 'El archivo pesa más de 150 MB.' }, { Connection: 'close' });
  const nombre = crypto.randomBytes(12).toString('hex') + ext;
  const destino = path.join(UPLOADS_DIR, nombre);
  const out = fs.createWriteStream(destino);
  let size = 0, cortado = false;
  req.on('data', c => {
    size += c.length;
    if (size > MAX_UPLOAD && !cortado) {
      cortado = true; req.unpipe(out); out.destroy(); fs.unlink(destino, () => {});
      json(res, 413, { error: 'El archivo pesa más de 150 MB.' }, { Connection: 'close' });
      req.resume();
    }
  });
  req.pipe(out);
  out.on('finish', () => { if (!cortado) json(res, 200, { url: '/uploads/' + nombre, tipo: MEDIA_EXT[ext] }); });
  out.on('error', () => { if (!cortado) { cortado = true; json(res, 500, { error: 'No se pudo guardar el archivo.' }); } });
  req.on('aborted', () => { out.destroy(); fs.unlink(destino, () => {}); });
}

/* -------------------- Validación de cada tipo de contenido -------------------- */
function urlBoton(v) {
  v = txt(v, 300); if (!v) return '';
  return /^(https?:\/\/|mailto:|tel:|#|\/)/i.test(v) ? v : 'https://' + v;
}
function construir(tipo, b, previo) {
  const ahora = new Date().toISOString();
  const item = previo ? Object.assign({}, previo) : { id: crypto.randomUUID(), creado: ahora };
  item.actualizado = ahora;
  item.titulo = txt(b.titulo, 120);
  item.texto = txt(b.texto, 3000);
  item.activa = b.activa !== false;
  item.media = mediaValida(b.media);
  if (!item.titulo && !item.texto && !item.media) throw new Error('Agrega al menos un título, un texto o una foto/video.');

  if (tipo === 'estados') {
    item.duracion = Object.prototype.hasOwnProperty.call(DURACIONES, b.duracion) ? b.duracion : '24h';
    const ms = DURACIONES[item.duracion];
    item.expiraEn = ms ? new Date(Date.now() + ms).toISOString() : null;
  }
  if (tipo === 'novedades') {
    if (!item.titulo) throw new Error('La novedad necesita un título.');
    item.layout = LAYOUTS.includes(b.layout) ? b.layout : 'derecha';
    if (['derecha', 'izquierda', 'arriba', 'fondo', 'tarjeta'].includes(item.layout) && !item.media && item.layout === 'fondo')
      throw new Error('El diseño con imagen de fondo necesita una foto o video.');
    const bt = txt(b.boton && b.boton.texto, 40), bu = urlBoton(b.boton && b.boton.url);
    item.boton = bt && bu ? { texto: bt, url: bu } : null;
  }
  return item;
}
function vigente(i) { return i.activa !== false && (!i.expiraEn || new Date(i.expiraEn) > new Date()); }
const masNuevo = (a, b) => (a.creado < b.creado ? 1 : -1);

/* --------------------------------- API ---------------------------------- */
async function api(req, res, u) {
  const p = u.pathname;
  const m = req.method;

  if (p === '/api/public' && m === 'GET') {
    const db = leerDB();
    return json(res, 200, {
      estados: db.estados.filter(vigente).sort(masNuevo),
      novedades: db.novedades.filter(vigente).sort(masNuevo),
      alertas: db.alertas.filter(vigente).sort(masNuevo)
    });
  }

  if (!p.startsWith('/api/admin/')) return json(res, 404, { error: 'No encontrado' });

  /* Todo lo que cambia datos exige esta cabecera (frena ataques desde otras webs) */
  if (m !== 'GET' && req.headers['x-requested-with'] !== 'cf') return json(res, 403, { error: 'Solicitud no permitida' });

  if (p === '/api/admin/login' && m === 'POST') {
    const ip = ipDe(req); const espera = bloqueado(ip);
    if (espera) return json(res, 429, { error: 'Demasiados intentos. Espera ' + espera + ' minuto(s).' });
    let b; try { b = await leerCuerpo(req, 4096); } catch (e) { return json(res, 400, { error: 'Solicitud inválida' }); }
    const okU = seguroIgual(b.usuario || '', ADMIN_USER), okC = seguroIgual(b.clave || '', ADMIN_PASS);
    if (okU && okC) {
      intentos.delete(ip);
      return json(res, 200, { ok: true }, { 'Set-Cookie': cookieSesion(req, crearToken(), SESSION_MS / 1000) });
    }
    falloLogin(ip);
    return json(res, 401, { error: 'Usuario o contraseña incorrectos.' });
  }
  if (p === '/api/admin/logout' && m === 'POST')
    return json(res, 200, { ok: true }, { 'Set-Cookie': cookieSesion(req, '', 0) });

  if (!sesionValida(req)) return json(res, 401, { error: 'Sesión no iniciada' });

  if (p === '/api/admin/session') return json(res, 200, { ok: true });
  if (p === '/api/admin/upload' && m === 'PUT') return subir(req, res, u);
  if (p === '/api/admin/data' && m === 'GET') {
    const db = leerDB();
    return json(res, 200, {
      estados: db.estados.sort(masNuevo), novedades: db.novedades.sort(masNuevo), alertas: db.alertas.sort(masNuevo)
    });
  }

  const r = /^\/api\/admin\/(estados|novedades|alertas)(?:\/([\w-]+))?$/.exec(p);
  if (!r) return json(res, 404, { error: 'No encontrado' });
  const tipo = r[1], id = r[2];
  const db = leerDB();

  try {
    if (m === 'POST' && !id) {
      const item = construir(tipo, await leerCuerpo(req), null);
      db[tipo].push(item); guardarDB(db); return json(res, 201, item);
    }
    if (m === 'PUT' && id) {
      const i = db[tipo].findIndex(x => x.id === id);
      if (i < 0) return json(res, 404, { error: 'No existe' });
      const previo = db[tipo][i];
      const nuevo = construir(tipo, await leerCuerpo(req), previo);
      if (previo.media && (!nuevo.media || nuevo.media.url !== previo.media.url)) borrarMedia(previo.media);
      db[tipo][i] = nuevo; guardarDB(db); return json(res, 200, nuevo);
    }
    if (m === 'DELETE' && id) {
      const i = db[tipo].findIndex(x => x.id === id);
      if (i < 0) return json(res, 404, { error: 'No existe' });
      borrarMedia(db[tipo][i].media); db[tipo].splice(i, 1); guardarDB(db);
      return json(res, 200, { ok: true });
    }
  } catch (e) {
    return json(res, 400, { error: e.message === 'json' || e.message === 'grande' ? 'Solicitud inválida' : e.message });
  }
  return json(res, 405, { error: 'Método no permitido' });
}

/* ---------------------------- Archivos estáticos ---------------------------- */
function enviar(req, res, archivo, extra) {
  fs.stat(archivo, (err, st) => {
    if (err || !st.isFile()) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('No encontrado'); }
    const tipo = MIME[path.extname(archivo).toLowerCase()] || 'application/octet-stream';
    const h = Object.assign({ 'Content-Type': tipo, 'Accept-Ranges': 'bytes', 'X-Content-Type-Options': 'nosniff' }, extra || {});
    let ini = 0, fin = st.size - 1, code = 200;
    const rg = /^bytes=(\d*)-(\d*)$/.exec(req.headers.range || '');
    if (rg && (rg[1] || rg[2])) { /* necesario para que los videos funcionen en iPhone/Safari */
      if (!rg[1]) ini = Math.max(0, st.size - parseInt(rg[2], 10));
      else { ini = parseInt(rg[1], 10); if (rg[2]) fin = Math.min(fin, parseInt(rg[2], 10)); }
      if (ini > fin || ini >= st.size) { res.writeHead(416, { 'Content-Range': 'bytes */' + st.size }); return res.end(); }
      code = 206; h['Content-Range'] = 'bytes ' + ini + '-' + fin + '/' + st.size;
    }
    h['Content-Length'] = fin - ini + 1;
    res.writeHead(code, h);
    if (req.method === 'HEAD') return res.end();
    fs.createReadStream(archivo, { start: ini, end: fin }).pipe(res);
  });
}
function resolver(base, rel) {
  let d; try { d = decodeURIComponent(rel); } catch (e) { return null; }
  const f = path.normalize(path.join(base, d));
  return f === base || f.startsWith(base + path.sep) ? f : null;
}

const server = http.createServer((req, res) => {
  const u = new URL(req.url, 'http://x');
  if (u.pathname.startsWith('/api/')) {
    api(req, res, u).catch(() => json(res, 500, { error: 'Error del servidor' }));
    return;
  }
  if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405); return res.end(); }

  if (u.pathname.startsWith('/uploads/')) {
    const f = resolver(UPLOADS_DIR, u.pathname.slice(9));
    if (!f) { res.writeHead(400); return res.end(); }
    return enviar(req, res, f, { 'Cache-Control': 'public, max-age=2592000, immutable' });
  }
  if (u.pathname === '/admin' || u.pathname === '/admin/')
    return enviar(req, res, path.join(PUBLIC_DIR, 'admin.html'),
      { 'Cache-Control': 'no-store', 'X-Robots-Tag': 'noindex, nofollow', 'X-Frame-Options': 'DENY' });

  const rel = u.pathname === '/' ? 'index.html' : u.pathname.slice(1);
  const f = resolver(PUBLIC_DIR, rel);
  if (!f || path.basename(f) === 'admin.html') { res.writeHead(404); return res.end('No encontrado'); }
  enviar(req, res, f, { 'Cache-Control': 'no-cache' });
});

server.listen(PORT, () => {
  console.log('Confinanzas listo en http://localhost:' + PORT + '  (panel: /admin)');
  limpiarHuerfanos(); setInterval(limpiarHuerfanos, 6 * 3600e3).unref();
});
