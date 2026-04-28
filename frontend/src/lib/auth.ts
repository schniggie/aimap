/**
 * Token bridge between Clerk and the API client.
 *
 * ClerkTokenBridge (in main.tsx) registers getToken() from useAuth().
 * The API client calls getAuthToken() to attach Bearer tokens to requests.
 */

let _getToken: (() => Promise<string | null>) | null = null;

export function setTokenGetter(getter: () => Promise<string | null>) {
  _getToken = getter;
}

export async function getAuthToken(): Promise<string | null> {
  if (!_getToken) return null;
  return _getToken();
}
