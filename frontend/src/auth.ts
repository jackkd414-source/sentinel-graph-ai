/**
 * Session-scoped credential store.
 *
 * Holds one of two things, and the API cannot tell them apart because both
 * travel in the same Authorization header:
 *   - a login session token from POST /api/auth/login (the normal case), or
 *   - the shared SG_AUTH_TOKEN, for headless or scripted use.
 *
 * localStorage is deliberately NOT used: it is disk-backed and survives the
 * session, so a shared machine would keep the analyst's credential indefinitely.
 * sessionStorage is cleared when the tab closes and is the weakest storage that
 * still survives in-app navigation.
 *
 * The value is never rendered, logged, or interpolated into error text. Only the
 * Authorization header carries it.
 */
const KEY = "sg_auth_token";

let memoryToken = "";

export function getToken(): string {
  if (memoryToken) return memoryToken;
  try {
    return sessionStorage.getItem(KEY) || "";
  } catch {
    return "";
  }
}

export function setToken(token: string): void {
  const value = token.trim();
  memoryToken = value;
  try {
    if (value) sessionStorage.setItem(KEY, value);
    else sessionStorage.removeItem(KEY);
  } catch {
    /* storage blocked (private mode): memory-only fallback still works */
  }
  window.dispatchEvent(new Event("sg:auth-change"));
}

export function clearToken(): void {
  memoryToken = "";
  try {
    sessionStorage.removeItem(KEY);
  } catch {
    /* ignore */
  }
  window.dispatchEvent(new Event("sg:auth-change"));
}

export function hasToken(): boolean {
  return getToken().length > 0;
}

/** Fired when the API answers 401 so the shell can prompt for a token. */
export function notifyUnauthorized(): void {
  window.dispatchEvent(new Event("sg:unauthorized"));
}

/** Attach the bearer token to a raw fetch/RequestInit without mutating `init`. */
export function withAuth(headers?: HeadersInit): Record<string, string> {
  const merged: Record<string, string> = { ...(headers as Record<string, string> | undefined) };
  const token = getToken();
  if (token) merged.Authorization = `Bearer ${token}`;
  return merged;
}