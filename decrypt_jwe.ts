import { jwtDecrypt, base64url, calculateJwkThumbprint } from "jose";
import { hkdf } from "@panva/hkdf";

/** Optional local diagnostic helper. Production ingress uses Authwall. */
export async function decode({ token, secret, salt }: { token: string; secret: string; salt: string }) {
  if (!token || token.length > 16384 || !secret || !salt) throw new Error("Invalid session");
  const { payload } = await jwtDecrypt(token, async ({ kid, enc }) => {
    const length = enc === "A256CBC-HS512" ? 64 : enc === "A256GCM" ? 32 : 0;
    if (!length) throw new Error("Invalid session");
    const key = await hkdf("sha256", secret, salt, `Auth.js Generated Encryption Key (${salt})`, length);
    if (kid !== undefined) {
      const thumbprint = await calculateJwkThumbprint(
        { kty: "oct", k: base64url.encode(key) }, `sha${key.byteLength << 3}` as any,
      );
      if (kid !== thumbprint) throw new Error("Invalid session");
    }
    return key;
  }, {
    clockTolerance: 15,
    requiredClaims: ["exp", "sub"],
    keyManagementAlgorithms: ["dir"],
    contentEncryptionAlgorithms: ["A256GCM", "A256CBC-HS512"],
  });
  if (typeof payload.sub !== "string" || !payload.sub.trim()) throw new Error("Invalid session");
  return payload;
}

export async function handleRequest(req: Request) {
  const url = new URL(req.url);
  if (url.pathname === "/health" && req.method === "GET") return Response.json({ status: "ok" });
  if (url.pathname !== "/decrypt" || url.search) return new Response(null, { status: 404 });
  if (req.method !== "POST") return new Response(null, { status: 405 });
  if (!(req.headers.get("content-type") || "").startsWith("application/json")) return new Response(null, { status: 415 });
  try {
    const reader = req.body?.getReader();
    if (!reader) return new Response(null, { status: 400 });
    const chunks: Uint8Array[] = [];
    let length = 0;
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        length += value.length;
        if (length > 20000) return new Response(null, { status: 413 });
        chunks.push(value);
      }
    } finally { await reader.cancel(); }
    const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    // Secrets come from local configuration, never request query strings or bodies.
    if (typeof body.token !== "string" || body.secret || body.salt) return new Response(null, { status: 400 });
    const payload = await decode({ token: body.token, secret: process.env.JWT_SECRET || "", salt: process.env.JWT_SALT || "authjs.session-token" });
    return Response.json({ success: true, payload }, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return Response.json({ error: "Invalid session" }, { status: 401, headers: { "Cache-Control": "no-store" } });
  }
}

if (import.meta.main) {
  if (!process.env.JWT_SECRET) throw new Error("JWT_SECRET is required");
  Bun.serve({ port: Number(process.env.PORT || 3000), hostname: "127.0.0.1", maxRequestBodySize: 20000, idleTimeout: 10, fetch: handleRequest, development: false });
}
