// @vitest-environment node
import { describe, test, expect, vi, beforeEach } from "vitest";

// Mock server-only so it doesn't throw in test environment
vi.mock("server-only", () => ({}));

// Mock next/headers cookies
const mockSet = vi.fn();
const mockGet = vi.fn();
const mockDelete = vi.fn();

vi.mock("next/headers", () => ({
  cookies: vi.fn(() =>
    Promise.resolve({
      set: mockSet,
      get: mockGet,
      delete: mockDelete,
    })
  ),
}));

import { SignJWT } from "jose";

const { createSession, getSession } = await import("@/lib/auth");

const JWT_SECRET = new TextEncoder().encode("development-secret-key");

async function makeToken(payload: Record<string, any>, expiresIn = "7d") {
  return new SignJWT(payload)
    .setProtectedHeader({ alg: "HS256" })
    .setExpirationTime(expiresIn)
    .setIssuedAt()
    .sign(JWT_SECRET);
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("createSession", () => {
  test("sets an httpOnly cookie named auth-token", async () => {
    await createSession("user-1", "test@example.com");

    expect(mockSet).toHaveBeenCalledOnce();
    const [name, , options] = mockSet.mock.calls[0];
    expect(name).toBe("auth-token");
    expect(options.httpOnly).toBe(true);
  });

  test("cookie value is a valid signed JWT", async () => {
    await createSession("user-1", "test@example.com");

    const [, token] = mockSet.mock.calls[0];
    expect(typeof token).toBe("string");
    expect(token.split(".").length).toBe(3);
  });

  test("cookie expires approximately 7 days from now", async () => {
    await createSession("user-1", "test@example.com");

    const [, , options] = mockSet.mock.calls[0];
    const sevenDaysMs = 7 * 24 * 60 * 60 * 1000;
    const diff = options.expires.getTime() - Date.now();

    expect(diff).toBeGreaterThan(sevenDaysMs - 5000);
    expect(diff).toBeLessThanOrEqual(sevenDaysMs + 5000);
  });

  test("cookie has correct path and sameSite settings", async () => {
    await createSession("user-1", "test@example.com");

    const [, , options] = mockSet.mock.calls[0];
    expect(options.path).toBe("/");
    expect(options.sameSite).toBe("lax");
  });

  test("creates unique tokens for different users", async () => {
    await createSession("user-1", "alice@example.com");
    const [, token1] = mockSet.mock.calls[0];

    vi.clearAllMocks();

    await createSession("user-2", "bob@example.com");
    const [, token2] = mockSet.mock.calls[0];

    expect(token1).not.toBe(token2);
  });
});

describe("getSession", () => {
  test("returns null when no cookie is present", async () => {
    mockGet.mockReturnValue(undefined);

    const session = await getSession();
    expect(session).toBeNull();
  });

  test("returns null for an invalid token", async () => {
    mockGet.mockReturnValue({ value: "invalid.token.here" });

    const session = await getSession();
    expect(session).toBeNull();
  });

  test("returns null for an expired token", async () => {
    const token = await makeToken(
      { userId: "user-1", email: "test@example.com" },
      "-1s"
    );
    mockGet.mockReturnValue({ value: token });

    const session = await getSession();
    expect(session).toBeNull();
  });

  test("returns session payload for a valid token", async () => {
    await createSession("user-42", "hello@example.com");
    const token = mockSet.mock.calls[0][1];
    mockGet.mockReturnValue({ value: token });

    const session = await getSession();
    expect(session).not.toBeNull();
    expect(session?.userId).toBe("user-42");
    expect(session?.email).toBe("hello@example.com");
  });

  test("returned session includes expiresAt", async () => {
    await createSession("user-1", "test@example.com");
    const token = mockSet.mock.calls[0][1];
    mockGet.mockReturnValue({ value: token });

    const session = await getSession();
    expect(session?.expiresAt).toBeDefined();
  });

  test("returns null for a token signed with a different secret", async () => {
    const wrongSecret = new TextEncoder().encode("wrong-secret");
    const token = await new SignJWT({ userId: "user-1", email: "x@x.com" })
      .setProtectedHeader({ alg: "HS256" })
      .setExpirationTime("7d")
      .setIssuedAt()
      .sign(wrongSecret);
    mockGet.mockReturnValue({ value: token });

    const session = await getSession();
    expect(session).toBeNull();
  });
});
