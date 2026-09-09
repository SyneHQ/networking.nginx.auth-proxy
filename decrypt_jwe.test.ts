import { test, expect } from "bun:test";
import { EncryptJWT } from "jose";
import { hkdf } from "@panva/hkdf";
import { decode, handleRequest } from "./decrypt_jwe";
const secret = "unit-test-secret-with-at-least-32-bytes";
const salt = "authjs.session-token";
async function token(claims: Record<string, unknown>) {
  const key = await hkdf("sha256", secret, salt, `Auth.js Generated Encryption Key (${salt})`, 64);
  return new EncryptJWT(claims).setProtectedHeader({ alg: "dir", enc: "A256CBC-HS512" }).encrypt(key);
}
test("accepts Auth.js encrypted sessions and requires subject and expiry", async () => {
  const exp = Math.floor(Date.now() / 1000) + 60;
  expect((await decode({ token: await token({ sub: "user", exp }), secret, salt })).sub).toBe("user");
  for (const claims of [{ sub: "user" }, { exp }, { sub: "user", exp: 1 }, { sub: "", exp }]) {
    await expect(decode({ token: await token(claims), secret, salt })).rejects.toThrow();
  }
});
test("disallows query/body secrets and bounds streamed bodies", async () => {
  expect((await handleRequest(new Request("http://localhost/decrypt?secret=value"))).status).toBe(404);
  expect((await handleRequest(new Request("http://localhost/decrypt"))).status).toBe(405);
  expect((await handleRequest(new Request("http://localhost/decrypt", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token: "x", secret: "x" }) }))).status).toBe(400);
  expect((await handleRequest(new Request("http://localhost/decrypt", { method: "POST", headers: { "content-type": "application/json" }, body: "x".repeat(20001) }))).status).toBe(413);
});
