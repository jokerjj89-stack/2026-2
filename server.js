// 부스 QR 방문 카운터 — Node.js 서버 (Node 18+)
// 실행: ADMIN_PASSWORD=비밀번호 node server.js
// DATABASE_URL이 있으면 Postgres에, 없으면 data/data.json 파일에 저장합니다.
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = Number(process.env.PORT) || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin1234';
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, 'data', 'data.json');
const PUBLIC_URL = (process.env.PUBLIC_URL || '').replace(/\/+$/, '');
const SECRET = process.env.SESSION_SECRET ||
  crypto.createHash('sha256').update('booth-qr:' + ADMIN_PASSWORD).digest('hex');
const PUBLIC_DIR = path.join(__dirname, 'public');
const DOUBLE_SCAN_MS = 10_000; // 같은 기기가 10초 안에 다시 열면 중복 기록하지 않음

// ---------- 저장소 ----------
// 메모리(db)에 전체 데이터를 들고 통계를 계산하고, 변경은 곧바로 Postgres(또는 파일)에 기록합니다.
let db = { booths: [], visits: [] };
const DATABASE_URL = process.env.DATABASE_URL || '';
let pool = null;
if (DATABASE_URL) {
  const { Pool } = require('pg');
  const host = (() => { try { return new URL(DATABASE_URL).hostname; } catch { return ''; } })();
  const needSsl = process.env.PGSSL === '1' || /\./.test(host); // 외부 주소면 SSL, Render 내부 주소(점 없음)는 SSL 없음
  pool = new Pool({ connectionString: DATABASE_URL, ssl: needSsl ? { rejectUnauthorized: false } : false, max: 5 });
  pool.on('error', (e) => console.error('DB 연결 오류:', e.message));
}
const q = (text, params) => pool.query(text, params);

async function loadData() {
  if (!pool) {
    try {
      db = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
      db.booths ||= []; db.visits ||= [];
    } catch (e) {
      if (e.code !== 'ENOENT') { console.error('데이터 파일을 읽지 못했습니다:', e.message); process.exit(1); }
    }
    return;
  }
  await q(`CREATE TABLE IF NOT EXISTS booths (id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at BIGINT NOT NULL)`);
  await q(`CREATE TABLE IF NOT EXISTS visits (id BIGSERIAL PRIMARY KEY, booth_id TEXT NOT NULL, visitor_id TEXT NOT NULL, ts BIGINT NOT NULL)`);
  await q(`CREATE INDEX IF NOT EXISTS visits_booth_idx ON visits (booth_id)`);
  const booths = await q(`SELECT id, name, created_at FROM booths ORDER BY created_at, id`);
  const visits = await q(`SELECT booth_id, visitor_id, ts FROM visits ORDER BY id`);
  db.booths = booths.rows.map((r) => ({ id: r.id, name: r.name, createdAt: Number(r.created_at) }));
  db.visits = visits.rows.map((r) => ({ b: r.booth_id, v: r.visitor_id, t: Number(r.ts) }));
}

// 파일 저장(DB가 없을 때만)
let saveTimer = null;
function save() {
  if (pool) return;
  clearTimeout(saveTimer);
  saveTimer = setTimeout(flush, 200);
}
function flush() {
  if (pool) return;
  clearTimeout(saveTimer); saveTimer = null;
  fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
  const tmp = DATA_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db));
  fs.renameSync(tmp, DATA_FILE);
}
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, async () => { flush(); if (pool) await pool.end().catch(() => {}); process.exit(0); });

// 변경 작업: 메모리와 저장소를 함께 갱신
const store = {
  async addBooths(list) {
    if (pool) for (const b of list) await q(`INSERT INTO booths (id, name, created_at) VALUES ($1,$2,$3)`, [b.id, b.name, b.createdAt]);
    db.booths.push(...list); save();
  },
  async renameBooth(booth, name) {
    if (pool) await q(`UPDATE booths SET name=$2 WHERE id=$1`, [booth.id, name]);
    booth.name = name; save();
  },
  async resetBooth(id) {
    if (pool) await q(`DELETE FROM visits WHERE booth_id=$1`, [id]);
    db.visits = db.visits.filter((v) => v.b !== id); save();
  },
  async deleteBooth(id) {
    if (pool) { await q(`DELETE FROM visits WHERE booth_id=$1`, [id]); await q(`DELETE FROM booths WHERE id=$1`, [id]); }
    db.booths = db.booths.filter((b) => b.id !== id);
    db.visits = db.visits.filter((v) => v.b !== id); save();
  },
  async addVisit(v) {
    db.visits.push(v); save();
    if (pool) {
      try { await q(`INSERT INTO visits (booth_id, visitor_id, ts) VALUES ($1,$2,$3)`, [v.b, v.v, v.t]); }
      catch (e) { db.visits.splice(db.visits.indexOf(v), 1); throw e; }
    }
  },
};

const newId = (n = 6) => {
  const chars = 'abcdefghjkmnpqrstuvwxyz23456789';
  let s = ''; const b = crypto.randomBytes(n);
  for (const x of b) s += chars[x % chars.length];
  return s;
};

// ---------- 유틸 ----------
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach((p) => {
    const i = p.indexOf('='); if (i < 0) return;
    out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}
const sign = (v) => v + '.' + crypto.createHmac('sha256', SECRET).update(v).digest('hex').slice(0, 32);
function isAdmin(req) {
  const t = parseCookies(req).adm; if (!t) return false;
  const v = t.split('.')[0];
  const a = Buffer.from(sign(v)), b = Buffer.from(t);
  return a.length === b.length && crypto.timingSafeEqual(a, b) && Number(v) > Date.now();
}
function send(res, status, body, type = 'text/html; charset=utf-8', headers = {}) {
  res.writeHead(status, { 'Content-Type': type, 'Cache-Control': 'no-store', ...headers });
  res.end(body);
}
const json = (res, status, obj) => send(res, status, JSON.stringify(obj), 'application/json; charset=utf-8');
function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (c) => { data += c; if (data.length > 1e5) { reject(new Error('too large')); req.destroy(); } });
    req.on('end', () => resolve(data));
  });
}
function baseUrl(req) {
  if (PUBLIC_URL) return PUBLIC_URL;
  const proto = (req.headers['x-forwarded-proto'] || '').split(',')[0] || (req.socket.encrypted ? 'https' : 'http');
  return `${proto}://${req.headers['x-forwarded-host'] || req.headers.host}`;
}
function dayKey(ts) { // 한국 시간 기준 날짜
  return new Date(ts + 9 * 3600e3).toISOString().slice(0, 10);
}

// ---------- 통계 ----------
function stats() {
  const today = dayKey(Date.now());
  const per = new Map(db.booths.map((b) => [b.id, { scans: 0, visitors: new Set(), todayVisitors: new Set(), last: 0 }]));
  const allVisitors = new Set();
  const hourly = new Map();
  for (const v of db.visits) {
    const s = per.get(v.b); if (!s) continue;
    s.scans++; s.visitors.add(v.v); allVisitors.add(v.v);
    if (dayKey(v.t) === today) s.todayVisitors.add(v.v);
    if (v.t > s.last) s.last = v.t;
    const h = new Date(v.t + 9 * 3600e3).toISOString().slice(0, 13);
    hourly.set(h, (hourly.get(h) || 0) + 1);
  }
  return {
    now: Date.now(),
    totalVisitors: allVisitors.size,
    totalScans: db.visits.filter((v) => per.has(v.b)).length,
    booths: db.booths.map((b) => {
      const s = per.get(b.id);
      return { id: b.id, name: b.name, createdAt: b.createdAt, visitors: s.visitors.size, today: s.todayVisitors.size, scans: s.scans, last: s.last || null };
    }),
    hourly: [...hourly.entries()].sort().slice(-24).map(([h, n]) => ({ hour: h, scans: n })),
  };
}

// ---------- 방문(스캔) 페이지 ----------
async function scanPage(req, res, boothId) {
  const booth = db.booths.find((b) => b.id === boothId);
  if (!booth) return send(res, 404, shell('없는 부스', `<div class="card"><div class="mark bad">?</div><h1>등록되지 않은 QR입니다</h1><p>운영 부스에 문의해 주세요.</p></div>`));

  const cookies = parseCookies(req);
  let vid = cookies.vid;
  const headers = {};
  if (!vid || !/^[a-z0-9]{12,40}$/.test(vid)) {
    vid = newId(16);
    headers['Set-Cookie'] = `vid=${vid}; Path=/; Max-Age=${60 * 60 * 24 * 365}; SameSite=Lax; HttpOnly`;
  }
  const now = Date.now();
  const mine = db.visits.filter((v) => v.v === vid);
  const prevHere = mine.filter((v) => v.b === booth.id);
  const first = prevHere.length === 0;
  const lastHere = prevHere.length ? prevHere[prevHere.length - 1].t : 0;
  if (now - lastHere > DOUBLE_SCAN_MS) await store.addVisit({ b: booth.id, v: vid, t: now });

  const visitedIds = new Set([...mine.map((v) => v.b), booth.id]);
  const visitedCount = db.booths.filter((b) => visitedIds.has(b.id)).length;
  const total = db.booths.length;
  const dots = db.booths.map((b) => `<li class="${visitedIds.has(b.id) ? 'on' : ''}${b.id === booth.id ? ' here' : ''}" title="${esc(b.name)}"><span>${esc(b.name)}</span></li>`).join('');

  const body = `
  <div class="card">
    <div class="mark">${first ? '✓' : '↺'}</div>
    <p class="eyebrow">${first ? '방문이 기록되었어요' : '이미 방문한 부스예요'}</p>
    <h1>${esc(booth.name)}</h1>
    <p class="sub">${first ? '방문해 주셔서 감사합니다!' : '방문 기록은 한 번만 집계됩니다.'}</p>
    <div class="progress">
      <div class="ptext"><b>${visitedCount}</b> / ${total} 부스 방문</div>
      <div class="bar"><i style="width:${total ? Math.round((visitedCount / total) * 100) : 0}%"></i></div>
      <ul class="dots">${dots}</ul>
    </div>
  </div>`;
  send(res, 200, shell(booth.name + ' 방문 완료', body), undefined, headers);
}

function shell(title, body) {
  return `<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>${esc(title)}</title><link rel="stylesheet" href="/static/scan.css"></head><body>${body}</body></html>`;
}

// ---------- 라우터 ----------
const MIME = { '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.html': 'text/html; charset=utf-8', '.svg': 'image/svg+xml' };
function serveStatic(res, file) {
  const p = path.join(PUBLIC_DIR, path.normalize(file).replace(/^(\.\.[/\\])+/, ''));
  if (!p.startsWith(PUBLIC_DIR)) return send(res, 403, 'forbidden');
  fs.readFile(p, (err, data) => {
    if (err) return send(res, 404, 'not found', 'text/plain');
    send(res, 200, data, MIME[path.extname(p)] || 'application/octet-stream');
  });
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://x');
    const p = url.pathname;
    const m = req.method;

    if (p === '/') return send(res, 302, '', 'text/plain', { Location: '/admin' });
    if (p.startsWith('/static/')) return serveStatic(res, p.slice(8));
    if (p.startsWith('/s/') && m === 'GET') return scanPage(req, res, p.slice(3));
    if (p === '/healthz') return send(res, 200, 'ok', 'text/plain');

    if (p === '/admin/login' && m === 'POST') {
      const form = new URLSearchParams(await readBody(req));
      const pw = form.get('password') || '';
      const a = crypto.createHash('sha256').update(pw).digest(), b = crypto.createHash('sha256').update(ADMIN_PASSWORD).digest();
      if (!crypto.timingSafeEqual(a, b)) return send(res, 302, '', 'text/plain', { Location: '/admin?err=1' });
      const token = sign(String(Date.now() + 1000 * 60 * 60 * 24 * 14));
      return send(res, 302, '', 'text/plain', { Location: '/admin', 'Set-Cookie': `adm=${token}; Path=/; Max-Age=${60 * 60 * 24 * 14}; SameSite=Lax; HttpOnly` });
    }
    if (p === '/admin/logout') return send(res, 302, '', 'text/plain', { Location: '/admin', 'Set-Cookie': 'adm=; Path=/; Max-Age=0' });

    if (p === '/admin' || p === '/admin/qr') {
      if (!isAdmin(req)) return serveStatic(res, 'login.html');
      return serveStatic(res, p === '/admin' ? 'admin.html' : 'qr.html');
    }

    if (p.startsWith('/api/')) {
      if (!isAdmin(req)) return json(res, 401, { error: '로그인이 필요합니다.' });

      if (p === '/api/stats' && m === 'GET') return json(res, 200, { ...stats(), baseUrl: baseUrl(req) });

      if (p === '/api/booths' && m === 'POST') {
        const body = JSON.parse((await readBody(req)) || '{}');
        const names = (Array.isArray(body.names) ? body.names : [body.name])
          .map((s) => String(s || '').trim().slice(0, 60)).filter(Boolean);
        if (!names.length) return json(res, 400, { error: '부스 이름을 입력해 주세요.' });
        const added = names.map((name, i) => ({ id: newId(), name, createdAt: Date.now() + i }));
        await store.addBooths(added); return json(res, 201, { added });
      }

      if (p === '/api/export.csv' && m === 'GET') {
        const names = new Map(db.booths.map((b) => [b.id, b.name]));
        const rows = [['시간(KST)', '부스', '부스ID', '방문자ID']];
        for (const v of db.visits) if (names.has(v.b)) rows.push([new Date(v.t + 9 * 3600e3).toISOString().replace('T', ' ').slice(0, 19), names.get(v.b), v.b, v.v]);
        const st = stats();
        rows.push([], ['부스', '방문자 수(중복 제외)', '총 스캔 수']);
        for (const b of st.booths) rows.push([b.name, b.visitors, b.scans]);
        const csv = '﻿' + rows.map((r) => r.map((c) => `"${String(c ?? '').replace(/"/g, '""')}"`).join(',')).join('\r\n');
        return send(res, 200, csv, 'text/csv; charset=utf-8', { 'Content-Disposition': `attachment; filename="booth-visits-${dayKey(Date.now())}.csv"` });
      }

      const mm = p.match(/^\/api\/booths\/([a-z0-9]+)(\/reset)?$/);
      if (mm) {
        const booth = db.booths.find((b) => b.id === mm[1]);
        if (!booth) return json(res, 404, { error: '부스를 찾을 수 없습니다.' });
        if (mm[2] && m === 'POST') { await store.resetBooth(booth.id); return json(res, 200, { ok: true }); }
        if (m === 'PATCH') {
          const body = JSON.parse((await readBody(req)) || '{}');
          const name = String(body.name || '').trim().slice(0, 60);
          if (!name) return json(res, 400, { error: '부스 이름을 입력해 주세요.' });
          await store.renameBooth(booth, name); return json(res, 200, { booth });
        }
        if (m === 'DELETE') {
          await store.deleteBooth(booth.id); return json(res, 200, { ok: true });
        }
      }
      return json(res, 404, { error: 'not found' });
    }

    send(res, 404, 'not found', 'text/plain');
  } catch (e) {
    console.error(e);
    if (!res.headersSent) json(res, 500, { error: '서버 오류가 발생했습니다.' });
  }
});

// Render 무료 요금제는 15분간 접속이 없으면 서버가 잠듭니다.
// 깨어 있는 동안 10분마다 자기 주소를 열어 잠들지 않게 합니다. (KEEP_ALIVE=0 으로 끌 수 있음)
function keepAlive() {
  const url = process.env.RENDER_EXTERNAL_URL || PUBLIC_URL;
  if (!url || process.env.KEEP_ALIVE === '0') return;
  setInterval(() => { fetch(url + '/healthz').catch(() => {}); }, 10 * 60 * 1000).unref();
  console.log('잠들기 방지 켜짐:', url + '/healthz');
}

loadData().then(() => {
  server.listen(PORT, () => {
    console.log(`부스 QR 카운터 실행 중: http://localhost:${PORT}/admin  (저장소: ${pool ? 'Postgres' : DATA_FILE})`);
    if (!process.env.ADMIN_PASSWORD) console.log('⚠ ADMIN_PASSWORD가 설정되지 않아 기본 비밀번호(admin1234)를 사용합니다.');
    keepAlive();
  });
}).catch((e) => { console.error('데이터를 불러오지 못했습니다:', e.message); process.exit(1); });
