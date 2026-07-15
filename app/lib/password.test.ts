import assert from "node:assert/strict"
import test from "node:test"

import { hashPassword, verifyPassword } from "./password"

async function createLegacyHash(password: string, secret: string): Promise<string> {
  const data = new TextEncoder().encode(password + secret)
  const hash = await crypto.subtle.digest("SHA-256", data)
  return btoa(String.fromCharCode(...new Uint8Array(hash)))
}

test("hashPassword creates salted hashes and verifies the password", async () => {
  const firstHash = await hashPassword("correct horse battery staple")
  const secondHash = await hashPassword("correct horse battery staple")

  assert.match(firstHash, /^pbkdf2-sha256\$v1\$100000\$[A-Za-z0-9_-]{22}\$[A-Za-z0-9_-]{43}$/)
  assert.notEqual(firstHash, secondHash)
  assert.deepEqual(await verifyPassword("correct horse battery staple", firstHash), {
    valid: true,
    needsRehash: false,
  })
  assert.deepEqual(await verifyPassword("wrong password", firstHash), {
    valid: false,
    needsRehash: false,
  })
})

test("new hashes do not depend on AUTH_SECRET", async () => {
  const hash = await hashPassword("independent password")
  const previousSecret = process.env.AUTH_SECRET
  process.env.AUTH_SECRET = "rotated-secret"

  try {
    assert.equal((await verifyPassword("independent password", hash)).valid, true)
  } finally {
    if (previousSecret === undefined) {
      delete process.env.AUTH_SECRET
    } else {
      process.env.AUTH_SECRET = previousSecret
    }
  }
})

test("verifyPassword rejects malformed hashes", async () => {
  const malformedHashes = [
    "pbkdf2-sha256$bad$hash",
    "pbkdf2-sha256$v2$100000$YQ$Yg",
    "pbkdf2-sha256$v1$9999999$YQ$Yg",
    "pbkdf2-sha256$v1$100000$not+base64url$Yg",
  ]

  for (const hash of malformedHashes) {
    assert.equal((await verifyPassword("password", hash)).valid, false)
  }
})

test("verifyPassword supports legacy hashes and empty-secret registrations", async () => {
  const legacyHash = await createLegacyHash("legacy-password", "legacy-secret")
  const emptySecretHash = await createLegacyHash("empty-secret-password", "")

  assert.deepEqual(
    await verifyPassword("legacy-password", legacyHash, { legacySecrets: ["legacy-secret"] }),
    { valid: true, needsRehash: true },
  )
  assert.deepEqual(
    await verifyPassword("empty-secret-password", emptySecretHash, { legacySecrets: [""] }),
    { valid: true, needsRehash: true },
  )
  assert.equal(
    (await verifyPassword("wrong-password", legacyHash, { legacySecrets: ["legacy-secret"] })).valid,
    false,
  )
})
