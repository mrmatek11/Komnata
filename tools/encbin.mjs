// Binary AES-256-GCM, key from PBKDF2-SHA256 (300k), layout: salt(16) | iv(12) | ciphertext.
// Usage: node encbin.mjs enc|dec <password> < in > out
import { webcrypto as wc } from 'node:crypto';

const [mode, pw] = process.argv.slice(2);
if (!pw) { console.error('Brak hasła: dodaj sekret APP_PASSWORD w ustawieniach repo.'); process.exit(1); }

const chunks = [];
for await (const c of process.stdin) chunks.push(c);
const data = new Uint8Array(Buffer.concat(chunks));

const key = async (salt, use) => wc.subtle.deriveKey(
  { name: 'PBKDF2', salt, iterations: 300000, hash: 'SHA-256' },
  await wc.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveKey']),
  { name: 'AES-GCM', length: 256 }, false, [use]);

let out;
if (mode === 'enc') {
  const salt = wc.getRandomValues(new Uint8Array(16));
  const iv = wc.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await wc.subtle.encrypt({ name: 'AES-GCM', iv }, await key(salt, 'encrypt'), data));
  out = Buffer.concat([salt, iv, ct]);
} else {
  try {
    out = Buffer.from(await wc.subtle.decrypt({ name: 'AES-GCM', iv: data.subarray(16, 28) },
      await key(data.subarray(0, 16), 'decrypt'), data.subarray(28)));
  } catch {
    console.error('Złe hasło w sekrecie APP_PASSWORD.'); process.exit(1);
  }
}
process.stdout.write(out);
