// The backend is the source of truth; these legacy entry points remain only
// to produce explicit migration errors for older callers.
export async function syncCollection() {
  throw new Error('Local cache sync has been removed. Read server records directly.');
}
export async function syncAll() {
  throw new Error('Local cache sync has been removed. Read server records directly.');
}
export async function createViaBackend() {
  throw new Error('Use the server-backed service for this collection.');
}
export async function updateViaBackend() {
  throw new Error('Use the server-backed service for this collection.');
}
export async function deleteViaBackend() {
  throw new Error('Use the server-backed service for this collection.');
}
export async function getViaBackend() {
  throw new Error('Use the server-backed service for this collection.');
}
export const COLLECTION_MAP = Object.freeze({});
