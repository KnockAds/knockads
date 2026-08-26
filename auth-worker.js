// ============================================================================
// Knock Ads — Auth Worker (Cloudflare Workers + D1)
// ระบบล็อกอินสำหรับลูกค้าของ Knock Ads (แยกจาก Meta Ads Token ของแต่ละคน)
// ดูวิธี deploy ใน DEPLOY.md
// ============================================================================

// ปรับจำนวนรอบ PBKDF2 ให้พอดีกับ CPU-time limit ของ Cloudflare Workers Free Plan
// (ยิ่งมากยิ่งปลอดภัยแต่ยิ่งกิน CPU — ถ้าเจอ error เกี่ยว CPU time ให้ลดค่านี้ลง
//  หรืออัปเกรดเป็น Workers Paid ที่ $5/เดือน ซึ่งเพิ่ม CPU time limit มหาศาล)
const PBKDF2_ITERATIONS = 30000;
const SESSION_HOURS = 24; // อายุ session แบบ sliding (ต่ออายุอัตโนมัติทุกครั้งที่ verify สำเร็จ)

// ใส่โดเมนที่อนุญาตให้เรียก API นี้ได้ (เพิ่ม localhost หรือโดเมนอื่นได้ตอน dev)
const ALLOWED_ORIGINS = ["https://knockads.github.io"];

function corsHeaders(origin) {
  const allowOrigin = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Methods": "GET,POST,PATCH,DELETE,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin",
  };
}

function json(data, status, headers) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

// ---------- utils: base64url ----------
function b64url(bytes) {
  let bin = "";
  const arr = new Uint8Array(bytes);
  for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlToBytes(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}
function utf8(str) {
  return new TextEncoder().encode(str);
}

// ---------- password hashing (PBKDF2-SHA256 via crypto.subtle, native & fast) ----------
async function pbkdf2(password, saltBytes, iterations) {
  const keyMaterial = await crypto.subtle.importKey("raw", utf8(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: saltBytes, iterations, hash: "SHA-256" },
    keyMaterial,
    256
  );
  return new Uint8Array(bits);
}
function randomBytes(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}
async function hashPassword(password) {
  const salt = randomBytes(16);
  const hash = await pbkdf2(password, salt, PBKDF2_ITERATIONS);
  return `${PBKDF2_ITERATIONS}$${b64url(salt)}$${b64url(hash)}`;
}
async function verifyPassword(password, stored) {
  const parts = String(stored || "").split("$");
  if (parts.length !== 3) return false;
  const iterations = parseInt(parts[0], 10);
  const salt = b64urlToBytes(parts[1]);
  const expected = b64urlToBytes(parts[2]);
  const actual = await pbkdf2(password, salt, iterations);
  if (actual.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < actual.length; i++) diff |= actual[i] ^ expected[i];
  return diff === 0;
}

// ---------- session tokens (HMAC-SHA256 signed, not encrypted — payload has no secrets) ----------
async function hmacKey(secret) {
  return crypto.subtle.importKey("raw", utf8(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}
async function signToken(payloadObj, secret) {
  const payload = b64url(utf8(JSON.stringify(payloadObj)));
  const key = await hmacKey(secret);
  const sig = await crypto.subtle.sign("HMAC", key, utf8(payload));
  return `${payload}.${b64url(sig)}`;
}
async function verifyToken(token, secret) {
  if (!token || typeof token !== "string" || token.indexOf(".") === -1) return null;
  const dot = token.indexOf(".");
  const payload = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  const key = await hmacKey(secret);
  let valid = false;
  try {
    valid = await crypto.subtle.verify("HMAC", key, b64urlToBytes(sig), utf8(payload));
  } catch (e) {
    return null;
  }
  if (!valid) return null;
  try {
    const obj = JSON.parse(new TextDecoder().decode(b64urlToBytes(payload)));
    if (!obj.exp || obj.exp < Date.now()) return null;
    return obj;
  } catch (e) {
    return null;
  }
}

function randomPassword(len) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
  const bytes = randomBytes(len || 10);
  let out = "";
  for (let i = 0; i < bytes.length; i++) out += chars[bytes[i] % chars.length];
  return out;
}

// ---------- auth helpers ----------
async function getAuthedUser(request, env) {
  const authz = request.headers.get("Authorization") || "";
  const m = authz.match(/^Bearer\s+(.+)$/i);
  if (!m) return null;
  const payload = await verifyToken(m[1], env.AUTH_SECRET);
  if (!payload || !payload.u) return null;
  const row = await env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(payload.u).first();
  if (!row) return null;
  if (row.status !== "active") return null;
  if (row.expires_at && row.expires_at < Date.now()) return null;
  return row;
}
async function issueSessionToken(row, secret) {
  const now = Date.now();
  const payload = {
    u: row.username,
    r: row.role,
    iat: now,
    exp: now + SESSION_HOURS * 3600 * 1000,
  };
  const token = await signToken(payload, secret);
  return { token, exp: payload.exp };
}
function sessionUserPayload(row, tokenInfo) {
  return {
    token: tokenInfo.token,
    username: row.username,
    role: row.role,
    displayName: row.display_name || row.username,
    expiresAt: row.expires_at || null,
    sessionExpiresAt: tokenInfo.exp,
  };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin") || "";
    const headers = corsHeaders(origin);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers });
    }

    try {
      // ---- POST /setup — สร้างแอดมินคนแรก (ใช้ได้แค่ตอนยังไม่มี user ในระบบเลย) ----
      if (url.pathname === "/setup" && request.method === "POST") {
        const countRow = await env.DB.prepare("SELECT COUNT(*) as c FROM users").first();
        if (countRow && countRow.c > 0) {
          return json({ error: "ตั้งค่าระบบไปแล้ว กรุณาเข้าสู่ระบบตามปกติ" }, 403, headers);
        }
        const body = await request.json();
        const username = String(body.username || "").trim().toLowerCase();
        const password = String(body.password || "");
        if (!/^[a-z0-9_.\-]{3,32}$/.test(username)) {
          return json({ error: "username ต้องเป็นตัวอักษร a-z, ตัวเลข, _ . - ความยาว 3-32 ตัว" }, 400, headers);
        }
        if (password.length < 8) {
          return json({ error: "password ต้องมีอย่างน้อย 8 ตัวอักษร" }, 400, headers);
        }
        const hash = await hashPassword(password);
        const now = Date.now();
        await env.DB.prepare(
          "INSERT INTO users (username, password_hash, role, status, display_name, expires_at, created_at, updated_at, note) VALUES (?, ?, 'admin', 'active', ?, NULL, ?, ?, 'บัญชีแอดมินแรกเริ่ม')"
        ).bind(username, hash, username, now, now).run();
        return json({ ok: true }, 200, headers);
      }

      // ---- POST /login ----
      if (url.pathname === "/login" && request.method === "POST") {
        const body = await request.json();
        const username = String(body.username || "").trim().toLowerCase();
        const password = String(body.password || "");
        const row = await env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(username).first();
        if (!row) return json({ error: "ไม่พบผู้ใช้นี้ หรือรหัสผ่านไม่ถูกต้อง" }, 401, headers);
        const ok = await verifyPassword(password, row.password_hash);
        if (!ok) return json({ error: "ไม่พบผู้ใช้นี้ หรือรหัสผ่านไม่ถูกต้อง" }, 401, headers);
        if (row.status !== "active") return json({ error: "บัญชีนี้ถูกระงับการใช้งาน กรุณาติดต่อผู้ดูแลระบบ" }, 403, headers);
        if (row.expires_at && row.expires_at < Date.now()) return json({ error: "บัญชีนี้หมดอายุแล้ว กรุณาติดต่อผู้ดูแลระบบ" }, 403, headers);
        const tokenInfo = await issueSessionToken(row, env.AUTH_SECRET);
        return json(sessionUserPayload(row, tokenInfo), 200, headers);
      }

      // ---- POST /verify — เช็ค token + สถานะล่าสุดใน DB สด (สำหรับ revoke ได้ทันที) แล้วต่ออายุ session ----
      if (url.pathname === "/verify" && request.method === "POST") {
        const row = await getAuthedUser(request, env);
        if (!row) return json({ error: "เซสชันหมดอายุหรือไม่ถูกต้อง กรุณาเข้าสู่ระบบใหม่" }, 401, headers);
        const tokenInfo = await issueSessionToken(row, env.AUTH_SECRET);
        return json(sessionUserPayload(row, tokenInfo), 200, headers);
      }

      // ---- GET /admin/users — list (admin only) ----
      if (url.pathname === "/admin/users" && request.method === "GET") {
        const me = await getAuthedUser(request, env);
        if (!me || me.role !== "admin") return json({ error: "ต้องเป็นแอดมินเท่านั้น" }, 403, headers);
        const { results } = await env.DB.prepare(
          "SELECT username, role, status, display_name, expires_at, created_at, updated_at, note FROM users ORDER BY created_at DESC"
        ).all();
        return json({ users: results }, 200, headers);
      }

      // ---- POST /admin/users — create (admin only) ----
      if (url.pathname === "/admin/users" && request.method === "POST") {
        const me = await getAuthedUser(request, env);
        if (!me || me.role !== "admin") return json({ error: "ต้องเป็นแอดมินเท่านั้น" }, 403, headers);
        const body = await request.json();
        const username = String(body.username || "").trim().toLowerCase();
        if (!/^[a-z0-9_.\-]{3,32}$/.test(username)) {
          return json({ error: "username ต้องเป็นตัวอักษร a-z, ตัวเลข, _ . - ความยาว 3-32 ตัว" }, 400, headers);
        }
        const existing = await env.DB.prepare("SELECT username FROM users WHERE username = ?").bind(username).first();
        if (existing) return json({ error: "มี username นี้อยู่แล้ว" }, 409, headers);
        const suppliedPassword = body.password ? String(body.password) : "";
        const password = suppliedPassword.length >= 8 ? suppliedPassword : randomPassword(10);
        const hash = await hashPassword(password);
        const now = Date.now();
        const expiresAt = body.expiresAt ? Number(body.expiresAt) : null;
        const role = body.role === "admin" ? "admin" : "customer";
        const displayName = body.displayName ? String(body.displayName) : username;
        await env.DB.prepare(
          "INSERT INTO users (username, password_hash, role, status, display_name, expires_at, created_at, updated_at, note) VALUES (?, ?, ?, 'active', ?, ?, ?, ?, ?)"
        ).bind(username, hash, role, displayName, expiresAt, now, now, body.note ? String(body.note) : "").run();
        return json({ ok: true, username, password: suppliedPassword.length >= 8 ? undefined : password }, 200, headers);
      }

      // ---- PATCH/DELETE /admin/users/:username (admin only) ----
      const userMatch = url.pathname.match(/^\/admin\/users\/([^/]+)$/);
      if (userMatch && (request.method === "PATCH" || request.method === "DELETE")) {
        const me = await getAuthedUser(request, env);
        if (!me || me.role !== "admin") return json({ error: "ต้องเป็นแอดมินเท่านั้น" }, 403, headers);
        const username = decodeURIComponent(userMatch[1]).toLowerCase();

        if (request.method === "DELETE") {
          if (username === me.username) return json({ error: "ลบบัญชีตัวเองไม่ได้" }, 400, headers);
          await env.DB.prepare("DELETE FROM users WHERE username = ?").bind(username).run();
          return json({ ok: true }, 200, headers);
        }

        const body = await request.json();
        const sets = [];
        const binds = [];
        if (body.status && ["active", "disabled"].includes(body.status)) {
          sets.push("status = ?");
          binds.push(body.status);
        }
        if (body.expiresAt !== undefined) {
          sets.push("expires_at = ?");
          binds.push(body.expiresAt === null ? null : Number(body.expiresAt));
        }
        if (body.note !== undefined) {
          sets.push("note = ?");
          binds.push(String(body.note));
        }
        if (body.displayName !== undefined) {
          sets.push("display_name = ?");
          binds.push(String(body.displayName));
        }
        if (body.password) {
          if (String(body.password).length < 8) return json({ error: "password ต้องมีอย่างน้อย 8 ตัวอักษร" }, 400, headers);
          sets.push("password_hash = ?");
          binds.push(await hashPassword(String(body.password)));
        }
        if (!sets.length) return json({ error: "ไม่มีข้อมูลให้อัปเดต" }, 400, headers);
        sets.push("updated_at = ?");
        binds.push(Date.now());
        binds.push(username);
        await env.DB.prepare(`UPDATE users SET ${sets.join(", ")} WHERE username = ?`).bind(...binds).run();
        return json({ ok: true }, 200, headers);
      }

      return json({ error: "not found" }, 404, headers);
    } catch (e) {
      return json({ error: "เกิดข้อผิดพลาดที่เซิร์ฟเวอร์: " + (e && e.message ? e.message : String(e)) }, 500, headers);
    }
  },
};
