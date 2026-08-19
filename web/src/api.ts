let token = sessionStorage.getItem('lattice-security-token') ?? '';

export function setToken(value: string) {
  token = value.trim();
  if (token) sessionStorage.setItem('lattice-security-token', token);
  else sessionStorage.removeItem('lattice-security-token');
}

export function getToken() { return token; }

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (token) headers.set('Authorization', `Bearer ${token}`);
  if (init.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  const response = await fetch(path, { ...init, headers });
  if (!response.ok) {
    const error = await response.json().catch(() => ({ message: response.statusText }));
    throw new Error(error.path ? `${error.path}: ${error.message}` : error.message);
  }
  if (response.status === 204) return undefined as T;
  return response.json();
}

export function download(name: string, value: unknown) {
  const link = document.createElement('a');
  link.href = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' }));
  link.download = name;
  link.click();
  URL.revokeObjectURL(link.href);
}
