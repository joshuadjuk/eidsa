const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { streamEvents } = require('../lib/jsonstream');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'eidsa-stream-'));
test.after(() => fs.rmSync(tmp, { recursive: true, force: true }));

async function read(content) {
  const f = path.join(tmp, `f${Math.random().toString(36).slice(2)}.json`);
  fs.writeFileSync(f, content);
  const items = [];
  const info = await streamEvents(f, o => items.push(o));
  return { items, info };
}

test('root array', async () => {
  const { items, info } = await read(JSON.stringify([{ id: 1, a: { b: [1, 2] } }, { id: 2 }]));
  assert.deepEqual(items.map(i => i.id), [1, 2]);
  assert.equal(info.truncated, false);
});

test('Graph { value: [...] } wrapper', async () => {
  const { items } = await read(JSON.stringify({ '@odata.context': 'x', value: [{ id: 'a' }, { id: 'b' }] }));
  assert.deepEqual(items.map(i => i.id), ['a', 'b']);
});

test('truncated export keeps every complete event', async () => {
  const full = JSON.stringify([{ id: 1 }, { id: 2, s: 'x' }, { id: 3, nested: { deep: true } }]);
  const { items, info } = await read(full.slice(0, full.length - 12));
  assert.deepEqual(items.map(i => i.id), [1, 2]);
  assert.equal(info.truncated, true);
});

test('strings containing braces, brackets, quotes and escapes', async () => {
  const obj = { id: 1, s: 'a {b} [c] "q" \\ }]', u: 'ü 中文 😀' };
  const { items } = await read(JSON.stringify([obj]));
  assert.deepEqual(items[0], obj);
});

test('events spanning stream chunks (> 1 MB)', async () => {
  const big = Array.from({ length: 3000 }, (_, i) => ({ id: i, pad: 'x'.repeat(800), t: 'é'.repeat(50) }));
  const { items } = await read(JSON.stringify(big));
  assert.equal(items.length, 3000);
  assert.equal(items[2999].id, 2999);
  assert.equal(items[1234].t, 'é'.repeat(50));
});

test('file with no events array', async () => {
  const { items, info } = await read('{"error":"nope"}');
  assert.equal(items.length, 0);
  assert.equal(info.truncated, false);
});
