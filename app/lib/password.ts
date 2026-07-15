const PASSWORD_HASH_PREFIX = "pbkdf2-sha256"
const PASSWORD_HASH_VERSION = "v1"
const PASSWORD_HASH_ITERATIONS = 100_000
const MIN_PASSWORD_HASH_ITERATIONS = 10_000
const MAX_PASSWORD_HASH_ITERATIONS = 1_000_000
const PASSWORD_SALT_BYTES = 16
const PASSWORD_HASH_BYTES = 32
const LEGACY_HASH_PATTERN = /^[A-Za-z0-9+/]{43}=$/
const BASE64_URL_PATTERN = /^[A-Za-z0-9_-]+$/

export interface PasswordVerification {
  valid: boolean
  needsRehash: boolean
}

function toBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
}

function toBase64Url(bytes: Uint8Array): string {
  return toBase64(bytes)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "")
}

function fromBase64Url(value: string): Uint8Array {
  if (!BASE64_URL_PATTERN.test(value)) {
    throw new Error("Invalid base64url value")
  }

  const base64 = value
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(Math.ceil(value.length / 4) * 4, "=")
  const decoded = atob(base64)
  return Uint8Array.from(decoded, char => char.charCodeAt(0))
}

async function derivePasswordHash(
  password: string,
  salt: Uint8Array,
  iterations: number,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  )
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt,
      iterations,
    },
    key,
    PASSWORD_HASH_BYTES * 8,
  )

  return new Uint8Array(bits)
}

async function legacyPasswordHash(password: string, secret: string): Promise<string> {
  const data = new TextEncoder().encode(password + secret)
  const hash = await crypto.subtle.digest("SHA-256", data)
  return toBase64(new Uint8Array(hash))
}

function constantTimeEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false

  let difference = 0
  for (let index = 0; index < left.length; index += 1) {
    difference |= left[index] ^ right[index]
  }
  return difference === 0
}

export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(PASSWORD_SALT_BYTES))
  const hash = await derivePasswordHash(password, salt, PASSWORD_HASH_ITERATIONS)

  return [
    PASSWORD_HASH_PREFIX,
    PASSWORD_HASH_VERSION,
    PASSWORD_HASH_ITERATIONS.toString(),
    toBase64Url(salt),
    toBase64Url(hash),
  ].join("$")
}

export async function verifyPassword(
  password: string,
  encodedHash: string,
  options: { legacySecrets?: readonly string[] } = {},
): Promise<PasswordVerification> {
  if (!encodedHash.startsWith(`${PASSWORD_HASH_PREFIX}$`)) {
    if (!LEGACY_HASH_PATTERN.test(encodedHash)) {
      return { valid: false, needsRehash: false }
    }

    const secrets = [...new Set(options.legacySecrets ?? [])]
    for (const secret of secrets) {
      if (await legacyPasswordHash(password, secret) === encodedHash) {
        return { valid: true, needsRehash: true }
      }
    }
    return { valid: false, needsRehash: false }
  }

  try {
    const parts = encodedHash.split("$")
    if (parts.length !== 5) return { valid: false, needsRehash: false }

    const [prefix, version, iterationsValue, saltValue, expectedHashValue] = parts
    if (prefix !== PASSWORD_HASH_PREFIX || version !== PASSWORD_HASH_VERSION) {
      return { valid: false, needsRehash: false }
    }
    if (!/^[1-9][0-9]*$/.test(iterationsValue)) {
      return { valid: false, needsRehash: false }
    }

    const iterations = Number(iterationsValue)
    if (
      !Number.isSafeInteger(iterations) ||
      iterations < MIN_PASSWORD_HASH_ITERATIONS ||
      iterations > MAX_PASSWORD_HASH_ITERATIONS
    ) {
      return { valid: false, needsRehash: false }
    }

    const salt = fromBase64Url(saltValue)
    const expectedHash = fromBase64Url(expectedHashValue)
    if (salt.length !== PASSWORD_SALT_BYTES || expectedHash.length !== PASSWORD_HASH_BYTES) {
      return { valid: false, needsRehash: false }
    }

    const actualHash = await derivePasswordHash(password, salt, iterations)
    const valid = constantTimeEqual(actualHash, expectedHash)
    return {
      valid,
      needsRehash: valid && iterations !== PASSWORD_HASH_ITERATIONS,
    }
  } catch {
    return { valid: false, needsRehash: false }
  }
}
