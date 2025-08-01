// Usage: bun run decrypt_jwe.ts <token> <secret> <salt>
import { jwtDecrypt, base64url, calculateJwkThumbprint } from "jose";
import { hkdf } from "@panva/hkdf"

const alg = "dir";
const enc = "A256GCM";

async function getDerivedEncryptionKey(
  enc: string,
  keyMaterial: Parameters<typeof hkdf>[1],
  salt: Parameters<typeof hkdf>[2]
) {
  let length: number
  switch (enc) {
    case "A256CBC-HS512":
      length = 64
      break
    case "A256GCM":
      length = 32
      break
    default:
      throw new Error("Unsupported JWT Content Encryption Algorithm")
  }
  return await hkdf(
    "sha256",
    keyMaterial,
    salt,
    `Auth.js Generated Encryption Key (${salt})`,
    length
  )
}

/** Decodes an Auth.js issued JWT. */
export async function decode(params: { token: string, secret: string, salt: string }) {
  const { token, secret, salt } = params;
  const secrets = Array.isArray(secret) ? secret : [secret];
  if (!token) return null;

  const { payload } = await jwtDecrypt(
    token,
    async ({ kid, enc }) => {
      for (const secret of secrets) {
        const encryptionSecret = await getDerivedEncryptionKey(
          enc,
          secret,
          salt
        );
        if (kid === undefined) return encryptionSecret;

        const thumbprint = await calculateJwkThumbprint(
          { kty: "oct", k: base64url.encode(encryptionSecret) },
          `sha${encryptionSecret.byteLength << 3}` as any
        );
        if (kid === thumbprint) return encryptionSecret;
      }

      throw new Error("no matching decryption secret");
    },
    {
      clockTolerance: 15,
      keyManagementAlgorithms: [alg],
      contentEncryptionAlgorithms: [enc, "A256CBC-HS512"],
    }
  );
  return payload;
}

(async () => {
  const [, , token, secret, salt] = process.argv;
  if (!token || !secret || !salt) {
    console.error("Usage: bun run decrypt_jwe.ts <token> <secret> <salt>");
    process.exit(1);
  }
  const result = await decode({ token, secret, salt });
  console.log(JSON.stringify(result));
})();