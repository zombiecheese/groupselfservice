import { afterEach, describe, expect, it } from "vitest";
import {
  checkAccountLockout,
  clearAccountLockout,
  recordLoginFailure,
  _resetForTests,
} from "../../src/application/login-lockout";

const USER = "alice.admin";

describe("login-lockout", () => {
  afterEach(() => {
    _resetForTests();
  });

  it("treats unknown accounts as unlocked with zero failures", () => {
    const status = checkAccountLockout("unknown.user");
    expect(status.locked).toBe(false);
    expect(status.consecutiveFailures).toBe(0);
  });

  it("counts consecutive failures and increments", () => {
    recordLoginFailure(USER);
    recordLoginFailure(USER);
    const status = checkAccountLockout(USER);
    expect(status.locked).toBe(false);
    expect(status.consecutiveFailures).toBe(2);
  });

  it("locks after the fifth failure with a positive retry-after window", () => {
    for (let i = 0; i < 4; i += 1) recordLoginFailure(USER);
    const beforeFifth = checkAccountLockout(USER);
    expect(beforeFifth.locked).toBe(false);
    const afterFifth = recordLoginFailure(USER);
    expect(afterFifth.locked).toBe(true);
    expect(afterFifth.retryAfterSeconds).toBeGreaterThan(0);
    const status = checkAccountLockout(USER);
    expect(status.locked).toBe(true);
    expect(status.retryAfterSeconds).toBeGreaterThan(0);
  });

  it("clears state on successful login", () => {
    recordLoginFailure(USER);
    recordLoginFailure(USER);
    clearAccountLockout(USER);
    const status = checkAccountLockout(USER);
    expect(status.locked).toBe(false);
    expect(status.consecutiveFailures).toBe(0);
  });

  it("treats usernames case-insensitively", () => {
    recordLoginFailure(USER.toUpperCase());
    const status = checkAccountLockout(USER.toLowerCase());
    expect(status.consecutiveFailures).toBe(1);
  });

  it("ignores blank usernames", () => {
    const status = recordLoginFailure("   ");
    expect(status.locked).toBe(false);
    expect(status.consecutiveFailures).toBe(0);
  });
});
