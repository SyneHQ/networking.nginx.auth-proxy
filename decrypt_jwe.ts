import { jwtDecrypt, base64url, calculateJwkThumbprint } from "jose";
import { hkdf } from "@panva/hkdf"

const alg = "dir";
const enc = "A256GCM";

// 🚀 In-memory cache for derived encryption keys
const encryptionKeyCache = new Map<string, Uint8Array>();
const CACHE_TTL = 12 * 60 * 60 * 1000; // 12 hours
const cacheTimestamps = new Map<string, number>();

// 🧹 Cleanup expired cache entries every 10 minutes
setInterval(() => {
  const now = Date.now();
  for (const [key, timestamp] of cacheTimestamps.entries()) {
    if (now - timestamp > CACHE_TTL) {
      encryptionKeyCache.delete(key);
      cacheTimestamps.delete(key);
      console.log(`🗑️ [Line 17] cleanupCache: Expired cache entry removed for key: ${key}`);
    }
  }
  console.log(`🗑️ [Line 23] cleanupCache: Expired cache entries removed`);
}, 600000);

async function getDerivedEncryptionKey(
  enc: string,
  keyMaterial: Parameters<typeof hkdf>[1],
  salt: Parameters<typeof hkdf>[2]
): Promise<Uint8Array> {
  console.log(`🔑 [Line 25] getDerivedEncryptionKey: Starting key derivation with enc=${enc}, salt=${salt}`);

  // Create cache key
  const cacheKey = `${enc}-${salt}-${JSON.stringify(keyMaterial)}`;

  // Check cache first
  if (encryptionKeyCache.has(cacheKey)) {
    const timestamp = cacheTimestamps.get(cacheKey);
    if (timestamp && Date.now() - timestamp < CACHE_TTL) {
      console.log(`⚡ [Line 33] getDerivedEncryptionKey: Cache hit for key derivation`);
      return encryptionKeyCache.get(cacheKey)!;
    }
  }

  let length: number
  switch (enc) {
    case "A256CBC-HS512":
      length = 64
      break
    case "A256GCM":
      length = 32
      break
    default:
      console.error(`❌ [Line 46] getDerivedEncryptionKey: Unsupported JWT Content Encryption Algorithm: ${enc}`);
      throw new Error("Unsupported JWT Content Encryption Algorithm")
  }

  console.log(`🔧 [Line 50] getDerivedEncryptionKey: Deriving key with length=${length}`);
  const derivedKey = await hkdf(
    "sha256",
    keyMaterial,
    salt,
    `Auth.js Generated Encryption Key (${salt})`,
    length
  );

  // Cache the result
  encryptionKeyCache.set(cacheKey, derivedKey);
  cacheTimestamps.set(cacheKey, Date.now());
  console.log(`💾 [Line 61] getDerivedEncryptionKey: Key cached successfully`);

  return derivedKey;
}

/** Decodes an Auth.js issued JWT. */
export async function decode(params: { token: string, secret: string, salt: string }) {
  console.log(`🔓 [Line 67] decode: Starting JWT decryption process`);
  const { token, secret, salt } = params;
  const secrets = Array.isArray(secret) ? secret : [secret];

  if (!token) {
    console.warn(`⚠️ [Line 72] decode: No token provided`);
    return null;
  }

  try {
    const { payload } = await jwtDecrypt(
      token,
      async ({ kid, enc }) => {
        console.log(`🔍 [Line 79] decode: Processing decryption with kid=${kid}, enc=${enc}`);
        for (const secret of secrets) {
          const encryptionSecret = await getDerivedEncryptionKey(
            enc,
            secret,
            salt
          );
          if (kid === undefined) {
            console.log(`✅ [Line 86] decode: Using encryption secret without kid verification`);
            return encryptionSecret;
          }

          const thumbprint = await calculateJwkThumbprint(
            { kty: "oct", k: base64url.encode(encryptionSecret) },
            `sha${encryptionSecret.byteLength << 3}` as any
          );
          if (kid === thumbprint) {
            console.log(`🎯 [Line 94] decode: Thumbprint matched, using encryption secret`);
            return encryptionSecret;
          }
        }

        console.error(`🚫 [Line 99] decode: No matching decryption secret found`);
        throw new Error("no matching decryption secret");
      },
      {
        clockTolerance: 15,
        keyManagementAlgorithms: [alg],
        contentEncryptionAlgorithms: [enc, "A256CBC-HS512"],
      }
    );

    console.log(`🎉 [Line 108] decode: JWT decryption successful`);
    return payload;
  } catch (error) {
    console.error(`💥 [Line 111] decode: JWT decryption failed - ${error}`);
    throw error;
  }
}

// 🚀 High-performance Bun server
const server = Bun.serve({
  port: process.env.PORT || 3000,
  hostname: process.env.HOSTNAME || "localhost",
  async fetch(req) {
    console.log(`📥 [Line 120] fetch: Incoming request - ${req.method} ${req.url}`);

    // Health check endpoint
    if (req.url.endsWith("/health")) {
      console.log(`💚 [Line 124] fetch: Health check requested`);
      return new Response(JSON.stringify({
        status: "ok",
        uptime: process.uptime(),
        cacheSize: encryptionKeyCache.size,
        timestamp: new Date().toISOString()
      }), {
        headers: { "Content-Type": "application/json" }
      });
    }

    // Helper function to create JSON response
    const createJsonResponse = (data: any, status: number = 200) => {
      return new Response(JSON.stringify(data), {
        status,
        headers: { "Content-Type": "application/json" }
      });
    };

    // Helper function to handle decryption process
    const handleDecrypt = async (token: string, secret: string, salt: string, requestType: string) => {
      try {
        console.log(`🔄 [Line 139] fetch: Processing ${requestType} decrypt request`);

        if (!token || !secret || !salt) {
          console.error(`❌ [Line 142] fetch: Missing required parameters in ${requestType} request`);
          return createJsonResponse({
            error: "Missing required parameters: token, secret, salt"
          }, 400);
        }

        const result = await decode({ token, secret, salt });
        console.log(`✅ [Line 151] fetch: ${requestType} decryption successful`);

        return createJsonResponse({
          success: true,
          payload: result
        });

      } catch (error) {
        console.error(`💥 [Line 160] fetch: ${requestType} decryption error - ${error}`);
        return createJsonResponse({
          error: error instanceof Error ? error.message : "Unknown error"
        }, 500);
      }
    };

    // Decrypt endpoint - POST
    if (req.method === "POST" && req.url.endsWith("/decrypt")) {
      const body = await req.json();
      const { token, secret, salt } = body as { token: string, secret: string, salt: string };
      return handleDecrypt(token, secret, salt, "POST");
    }

    // Decrypt endpoint - GET (backward compatibility)
    if (req.method === "GET" && req.url.includes("/decrypt")) {
      const url = new URL(req.url);
      const token = url.searchParams.get("token");
      const secret = url.searchParams.get("secret");
      const salt = url.searchParams.get("salt");
      return handleDecrypt(token || "", secret || "", salt || "", "GET");
    }

    // Default 404 response
    console.warn(`🔍 [Line 207] fetch: Route not found - ${req.method} ${req.url}`);
    return createJsonResponse({
      error: "Route not found. Available endpoints: POST /decrypt, GET /decrypt, GET /health"
    }, 404);
  },
  development: process.env.NODE_ENV !== "production",
});

console.log(`🚀 [Line 217] main: Bun server started on http://${server.hostname}:${server.port}`);
console.log(`📋 [Line 218] main: Available endpoints:`);
console.log(`   POST http://${server.hostname}:${server.port}/decrypt - Decrypt JWT with JSON body`);
console.log(`   GET  http://${server.hostname}:${server.port}/decrypt?token=...&secret=...&salt=... - Decrypt JWT with URL params`);
console.log(`   GET  http://${server.hostname}:${server.port}/health - Health check`);