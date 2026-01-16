// Client-side secret-key encryptor/decryptor using Web Crypto API

async function deriveKeyFromSecret(secret) {
  const enc = new TextEncoder();
  const digest = await crypto.subtle.digest('SHA-256', enc.encode(secret));
  return crypto.subtle.importKey('raw', digest, { name: 'AES-GCM' }, false, ['encrypt','decrypt']);
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
  const key = await deriveKeyFromSecret(secret);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, fileBytes);
  let payload;
  if (expirySeconds > 0) {
    const expiryUnix = Math.floor(Date.now() / 1000) + expirySeconds;
    const header = new ArrayBuffer(8);
    const view = new DataView(header);
    view.setBigUint64(0, BigInt(expiryUnix), false);
    // nonce + ciphertext
    const nonceCipher = new Uint8Array(iv.byteLength + ciphertext.byteLength);
    nonceCipher.set(iv, 0);
    nonceCipher.set(new Uint8Array(ciphertext), iv.byteLength);
    payload = new Uint8Array(header.byteLength + nonceCipher.byteLength);
    payload.set(new Uint8Array(header), 0);
    payload.set(nonceCipher, header.byteLength);
  } else {
    payload = new Uint8Array(iv.byteLength + ciphertext.byteLength);
    payload.set(iv, 0);
    payload.set(new Uint8Array(ciphertext), iv.byteLength);
  }
  return payload.buffer;
}

async function decryptPayloadBase64(b64, secret, withHeader) {
  const key = await deriveKeyFromSecret(secret);
  const payload = fromBase64(b64);
  let offset = 0;
  if (withHeader) {
    if (payload.byteLength < 8 + 12) throw new Error('Payload too small for header');
    const view = new DataView(payload);
    const expiry = Number(view.getBigUint64(0, false));
    if (expiry < Math.floor(Date.now() / 1000)) throw new Error('Payload expired');
    offset = 8;
  }
  const iv = payload.slice(offset, offset + 12);
  const ciphertext = payload.slice(offset + 12);
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return plaintext;
}

document.getElementById('encryptBtn').addEventListener('click', async () => {
  const fileInput = document.getElementById('fileInput');
  const secret = document.getElementById('secret').value;
  const expiry = parseInt(document.getElementById('expiry').value || '0', 10);
  if (!fileInput.files[0]) { alert('Choose a file to encrypt'); return; }
  const file = fileInput.files[0];
  const arr = await file.arrayBuffer();
  const payloadBuf = await encryptFileLike(arr, secret, expiry);
  document.getElementById('payloadArea').value = toBase64(payloadBuf);
});

document.getElementById('decryptBtn').addEventListener('click', async () => {
  const b64 = document.getElementById('payloadInput').value.trim();
  const secret = document.getElementById('secret').value;
  const expiry = parseInt(document.getElementById('expiry').value || '0', 10);
  const withHeader = expiry > 0;
  try {
    const plaintext = await decryptPayloadBase64(b64, secret, withHeader);
    const blob = new Blob([new Uint8Array(plaintext)], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const dl = document.getElementById('downloadLink');
    dl.href = url;
    dl.style.display = 'inline';
  } catch (e) {
    alert('Decrypt failed: ' + e.message);
  }
});
