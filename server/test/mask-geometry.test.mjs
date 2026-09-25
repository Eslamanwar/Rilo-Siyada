/**
 * padBox decides how much of the image a redaction actually covers, so it is
 * worth pinning down. It lives inside the content script's IIFE and cannot be
 * imported, so the function is lifted out of the source and evaluated here —
 * the test therefore fails loudly if it is renamed or reshaped.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const SRC = fileURLToPath(new URL('../../extension/interceptor.js', import.meta.url));
const source = readFileSync(SRC, 'utf8');

function liftSource(name) {
  const start = source.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `${name}() not found in interceptor.js`);
  let depth = 0;
  for (let i = source.indexOf('{', start); i < source.length; i++) {
    if (source[i] === '{') depth++;
    else if (source[i] === '}' && --depth === 0) return source.slice(start, i + 1);
  }
  throw new Error(`could not read the body of ${name}()`);
}

const constant = (name) => Number(new RegExp(`${name}\\s*=\\s*([\\d.]+)`).exec(source)[1]);

const PAD     = constant('BOX_PAD_RATIO');
const MIN_PAD = constant('MIN_BOX_PAD_PX');

const padBox = new Function(`
  const BOX_PAD_RATIO = ${PAD}, MIN_BOX_PAD_PX = ${MIN_PAD};
  ${liftSource('padBox')}
  return padBox;
`)();

test('a padded box strictly contains the model box', () => {
  const [x, y, w, h] = padBox([0.4, 0.5, 0.2, 0.05], 1000, 600);
  assert.ok(x < 0.4 && y < 0.5);
  assert.ok(x + w > 0.6 && y + h > 0.55);
});

test('padding grows with the box', () => {
  const small = padBox([0.4, 0.4, 0.10, 0.10], 1000, 1000);
  const large = padBox([0.4, 0.4, 0.40, 0.40], 1000, 1000);
  assert.ok(large[2] - 0.40 > small[2] - 0.10);
  assert.equal(Math.round((small[2] - 0.10) * 1e6) / 1e6, Math.round(0.10 * PAD * 2 * 1e6) / 1e6);
});

test('a hairline box still gets a usable pixel margin', () => {
  const [, , w, h] = padBox([0.5, 0.5, 0.001, 0.001], 1000, 1000);
  assert.ok(w * 1000 >= MIN_PAD * 2, `width ${w * 1000}px`);
  assert.ok(h * 1000 >= MIN_PAD * 2, `height ${h * 1000}px`);
});

test('padding never escapes the image', () => {
  for (const box of [[0, 0, 0.2, 0.2], [0.8, 0.9, 0.2, 0.1], [0, 0, 1, 1]]) {
    const [x, y, w, h] = padBox(box, 800, 800);
    assert.ok(x >= 0 && y >= 0, `origin ${x},${y}`);
    assert.ok(x + w <= 1 + 1e-9 && y + h <= 1 + 1e-9, `extent ${x + w},${y + h}`);
  }
});
