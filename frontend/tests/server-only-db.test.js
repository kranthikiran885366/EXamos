import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createServer } from 'vite';

test('application records are fetched from the server without a browser database', async () => {
  const vite = await createServer({ server: { middlewareMode: true }, appType: 'custom' });
  const originalFetch = globalThis.fetch;
  const originalIndexedDb = Object.getOwnPropertyDescriptor(globalThis, 'indexedDB');
  const requests = [];

  Object.defineProperty(globalThis, 'indexedDB', {
    configurable: true,
    get() {
      throw new Error('Application records must not access IndexedDB.');
    },
  });
  globalThis.fetch = async (url, init) => {
    requests.push({ url, method: init.method });
    const body = String(url).endsWith('/devices')
      ? JSON.stringify([{ id: 'server-device' }])
      : JSON.stringify({ status: 'ok' });
    return { ok: true, status: 200, text: async () => body, headers: {} };
  };

  try {
    const { all } = await vite.ssrLoadModule('/src/core/db/db.js');
    assert.deepEqual(await all('devices'), [{ id: 'server-device' }]);
    assert.equal(requests[0].url, '/api/v1/console/data/devices');
    await assert.rejects(all('keys'), /Unsupported server collection: keys/);
    await new Promise((resolve) => setTimeout(resolve, 10));
  } finally {
    globalThis.fetch = originalFetch;
    if (originalIndexedDb) Object.defineProperty(globalThis, 'indexedDB', originalIndexedDb);
    else delete globalThis.indexedDB;
    await vite.close();
  }
});
