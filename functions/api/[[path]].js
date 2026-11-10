const SESSION_SECONDS = 60 * 60 * 24 * 7;
const PBKDF2_ITERATIONS = 310000;

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers },
  });
}

function cookie(name, value, maxAge) {
  return `${name}=${value}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}

function clearCookie() {
  return "gata_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0";
}

function randomBytes(length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function toBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64Url(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  return Uint8Array.from(atob(padded), c => c.charCodeAt(0));
}

async function sha256(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return toBase64Url(new Uint8Array(digest));
}

async function passwordHash(password, saltBytes = randomBytes(16)) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: saltBytes, iterations: PBKDF2_ITERATIONS },
    key,
    256
  );
  return `pbkdf2-sha256$${PBKDF2_ITERATIONS}$${toBase64Url(saltBytes)}$${toBase64Url(new Uint8Array(bits))}`;
}

async function verifyPassword(password, stored) {
  const [algorithm, iterations, salt, expected] = stored.split("$");
  if (algorithm !== "pbkdf2-sha256" || Number(iterations) !== PBKDF2_ITERATIONS) return false;
  const actual = await passwordHash(password, fromBase64Url(salt));
  return actual === stored && actual.split("$")[3] === expected;
}

function readCookie(request, name) {
  const header = request.headers.get("Cookie") || "";
  for (const part of header.split(";")) {
    const index = part.indexOf("=");
    if (index < 0) continue;
    if (part.slice(0, index).trim() === name) return part.slice(index + 1).trim();
  }
  return null;
}

async function getUser(request, env) {
  const token = readCookie(request, "gata_session");
  if (!token) return null;
  const digest = await sha256(token);
  const row = await env.DB.prepare(
    "SELECT users.id, users.name, users.email, auth_sessions.expires_at FROM auth_sessions JOIN users ON users.id = auth_sessions.user_id WHERE auth_sessions.token_hash = ?"
  ).bind(digest).first();
  if (!row) return null;
  if (Date.parse(row.expires_at) <= Date.now()) {
    await env.DB.prepare("DELETE FROM auth_sessions WHERE token_hash = ?").bind(digest).run();
    return null;
  }
  return { id: row.id, name: row.name, email: row.email };
}

async function startSession(userId, env) {
  const token = toBase64Url(randomBytes(32));
  const digest = await sha256(token);
  const now = new Date();
  const expires = new Date(now.getTime() + SESSION_SECONDS * 1000);
  await env.DB.prepare("DELETE FROM auth_sessions WHERE expires_at <= ?").bind(now.toISOString()).run();
  await env.DB.prepare(
    "INSERT INTO auth_sessions (user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?)"
  ).bind(userId, digest, expires.toISOString(), now.toISOString()).run();
  return token;
}

async function parseBody(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

export async function onRequest(context) {
  const { request, env } = context;
  const path = new URL(request.url).pathname;
  if (!env.DB) return json({ error: "Banco D1 não está conectado ao projeto Pages." }, 503);

  if (path === "/api/health" && request.method === "GET") {
    return json({ status: "ok", service: "Memória Gata API" });
  }

  if (path === "/api/register" && request.method === "POST") {
    const data = await parseBody(request);
    if (!data) return json({ error: "Envie os dados em JSON." }, 400);
    const name = String(data.name || "").trim();
    const email = String(data.email || "").trim().toLowerCase();
    const password = String(data.password || "");
    if (name.length < 2 || name.length > 60) return json({ error: "O nome deve ter entre 2 e 60 caracteres." }, 400);
    if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ error: "Informe um e-mail válido." }, 400);
    if (password.length < 8 || password.length > 128) return json({ error: "A senha deve ter entre 8 e 128 caracteres." }, 400);
    const hash = await passwordHash(password);
    const now = new Date().toISOString();
    let userId;
    try {
      const result = await env.DB.prepare(
        "INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, ?)"
      ).bind(name, email, hash, now).run();
      userId = result.meta.last_row_id;
    } catch (error) {
      if (String(error).toLowerCase().includes("unique")) return json({ error: "Este e-mail já está cadastrado." }, 409);
      throw error;
    }
    const token = await startSession(userId, env);
    return json({ user: { id: userId, name, email } }, 201, { "Set-Cookie": cookie("gata_session", token, SESSION_SECONDS) });
  }

  if (path === "/api/login" && request.method === "POST") {
    const data = await parseBody(request);
    if (!data) return json({ error: "Envie os dados em JSON." }, 400);
    const email = String(data.email || "").trim().toLowerCase();
    const password = String(data.password || "");
    const user = await env.DB.prepare("SELECT id, name, email, password_hash FROM users WHERE email = ?").bind(email).first();
    if (!user || !(await verifyPassword(password, user.password_hash))) return json({ error: "E-mail ou senha incorretos." }, 401);
    const token = await startSession(user.id, env);
    return json({ user: { id: user.id, name: user.name, email: user.email } }, 200, { "Set-Cookie": cookie("gata_session", token, SESSION_SECONDS) });
  }

  if (path === "/api/me" && request.method === "GET") {
    return json({ user: await getUser(request, env) });
  }

  if (path === "/api/logout" && request.method === "POST") {
    const token = readCookie(request, "gata_session");
    if (token) await env.DB.prepare("DELETE FROM auth_sessions WHERE token_hash = ?").bind(await sha256(token)).run();
    return json({ message: "Você saiu da sua conta." }, 200, { "Set-Cookie": clearCookie() });
  }

  return json({ error: "Rota não encontrada." }, 404);
}

