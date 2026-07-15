import assert from "node:assert/strict"
import test from "node:test"

import { authSchema } from "./validation"

test("authSchema bounds credential input", () => {
  assert.equal(authSchema.safeParse({ username: "valid-user", password: "12345678" }).success, true)
  assert.equal(authSchema.safeParse({ username: "valid-user", password: "short" }).success, false)
  assert.equal(authSchema.safeParse({ username: "valid-user", password: "x".repeat(129) }).success, false)
  assert.equal(authSchema.safeParse({ username: "user@example.com", password: "12345678" }).success, false)
})
