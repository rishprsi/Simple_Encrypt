// Client-side secret-key encryptor/decryptor using Web Crypto API (PBKDF2 with salt)

async function deriveKeyPBKDF2(secret, salt, iterations) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'PBKDF2' }, false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: salt, iterations: iterations, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt','decrypt']
  );
}

function toBase64(arrayBuffer) {
  const bytes = new Uint8Array(arrayBuffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function fromBase64(b64){
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

async function encryptFileLike(fileBytes, secret, expirySeconds) {
  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);
  const iterations = 200000;
  const key = await deriveKeyPBKDF2(secret, salt, iterations);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, fileBytes);

  const expiryUnix = expirySeconds > 0 ? Math.floor(Date.now() / 1000) + expirySeconds : 0;
  const header = new Uint8Array(8);
  const headerView = new DataView(header.buffer);
  headerView.setBigUint64(0, BigInt(expiryUnix), false);

  const iterationsBytes = new Uint8Array(4);
  const iterView = new DataView(iterationsBytes.buffer);
  iterView.setUint32(0, iterations, false);

  // payload: header(8) + salt(16) + iterations(4) + iv(12) + ciphertext
  const payload = new Uint8Array(8 + 16 + 4 + 12 + ciphertext.byteLength);
  let off = 0;
  payload.set(header, off); off += 8;
  payload.set(salt, off); off += 16;
  payload.set(iterationsBytes, off); off += 4;
  payload.set(iv, off); off += 12;
  payload.set(new Uint8Array(ciphertext), off);

  return payload.buffer;
}

async function decryptPayloadBase64(b64, secret) {
  const payload = fromBase64(b64);
  if (payload.byteLength < 8 + 16 + 4 + 12) throw new Error('Invalid payload format or too short');
  const payloadBytes = new Uint8Array(payload);
  // Read expiry in first 8 bytes
  const expiry = Number(new DataView(payloadBytes.buffer).getBigUint64(0, false));
  const offset = 8;
  const salt = payloadBytes.slice(offset, offset + 16);
  const iterations = new DataView(payloadBytes.buffer).getUint32(offset + 16, false);
  const iv = payloadBytes.slice(offset + 20, offset + 32);
  const ciphertext = payloadBytes.slice(offset + 32);

  const key = await deriveKeyPBKDF2(secret, salt, iterations);
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);

  if (expiry !== 0 && expiry < Math.floor(Date.now() / 1000)) {
    throw new Error('Payload expired');
  }
  return plaintext;
}

document.getElementById('encryptBtn').addEventListener('click', async () => {
  const textInput = document.getElementById('textInput');
  const secret = document.getElementById('encryptSecret').value;
  const expiry = parseInt(document.getElementById('expiry').value || '0', 10);
  const text = textInput.value;
  if (!text) { alert('Enter text to encrypt'); return; }
  const enc = new TextEncoder();
  const arr = enc.encode(text);
  const payloadBuf = await encryptFileLike(arr.buffer, secret, expiry);
  document.getElementById('payloadArea').value = toBase64(payloadBuf);
});

document.getElementById('decryptBtn').addEventListener('click', async () => {
  const b64 = document.getElementById('payloadInput').value.trim();
  const secret = document.getElementById('decryptSecret').value;
  try {
    const plaintext = await decryptPayloadBase64(b64, secret);
    const bytes = new Uint8Array(plaintext);
    const text = new TextDecoder('utf-8').decode(bytes);
    const decryptedTextArea = document.getElementById('decryptedTextArea');
    const copyBtn = document.getElementById('copyTextBtn');
    decryptedTextArea.value = text;
    copyBtn.style.display = 'inline';
  } catch (e) {
    alert('Decrypt failed: ' + e.message);
  }
});
