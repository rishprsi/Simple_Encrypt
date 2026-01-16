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

async function encryptFileLike(fileBytes, secret, expirySeconds, filename) {
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

  const enc = new TextEncoder();
  const nameBytes = enc.encode(filename);
  const nameLen = new Uint8Array(1);
  nameLen[0] = nameBytes.byteLength;

  // payload: header(8) + salt(16) + iterations(4) + nameLen(1) + nameBytes + iv(12) + ciphertext
  const payload = new Uint8Array(8 + 16 + 4 + 1 + nameBytes.byteLength + 12 + ciphertext.byteLength);
  let off = 0;
  payload.set(header, off); off += 8;
  payload.set(salt, off); off += 16;
  payload.set(iterationsBytes, off); off += 4;
  payload.set(nameLen, off); off += 1;
  payload.set(nameBytes, off); off += nameBytes.byteLength;
  payload.set(iv, off); off += 12;
  payload.set(new Uint8Array(ciphertext), off);

  return payload.buffer;
}

async function decryptPayload(buffer, secret) {
  const payload = buffer;
  if (payload.byteLength < 8 + 16 + 4 + 1 + 12) throw new Error('Invalid payload format or too short');
  const payloadBytes = new Uint8Array(payload);
  // Read expiry in first 8 bytes
  const expiry = Number(new DataView(payloadBytes.buffer).getBigUint64(0, false));
  let offset = 8;
  const salt = payloadBytes.slice(offset, offset + 16);
  offset += 16;
  const iterations = new DataView(payloadBytes.buffer).getUint32(offset, false);
  offset += 4;
  const nameLen = payloadBytes[offset];
  offset += 1;
  const nameBytes = payloadBytes.slice(offset, offset + nameLen);
  const filename = new TextDecoder().decode(nameBytes);
  offset += nameLen;
  const iv = payloadBytes.slice(offset, offset + 12);
  offset += 12;
  const ciphertext = payloadBytes.slice(offset);

  const key = await deriveKeyPBKDF2(secret, salt, iterations);
  let plaintext;
  try {
    plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  } catch {
    throw new Error('Decryption failed: wrong secret key or corrupted payload');
  }

  if (expiry !== 0 && expiry < Math.floor(Date.now() / 1000)) {
    throw new Error('Payload expired');
  }
  return { plaintext, filename };
}

document.getElementById('encryptBtn').addEventListener('click', async () => {
  const secret = document.getElementById('encryptSecret').value;
  const expiry = parseInt(document.getElementById('expiry').value || '0', 10);
  const inputType = document.querySelector('input[name="inputType"]:checked').value;
  let arr, filename;
  if (inputType === 'text') {
    const textInput = document.getElementById('textInput');
    const text = textInput.value;
    if (!text) { alert('Enter text to encrypt'); return; }
    const enc = new TextEncoder();
    arr = enc.encode(text);
    filename = 'decrypted.txt';
  } else {
    const fileInput = document.getElementById('fileInput');
    if (!fileInput.files[0]) { alert('Choose a file to encrypt'); return; }
    const file = fileInput.files[0];
    arr = await file.arrayBuffer();
    filename = file.name;
  }
  const payloadBuf = await encryptFileLike(arr, secret, expiry, filename);
  document.getElementById('payloadArea').value = toBase64(payloadBuf);
  document.getElementById('copyPayloadBtn').style.display = 'inline';

  if (inputType === 'file') {
    const blob = new Blob([new Uint8Array(payloadBuf)], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const dl = document.getElementById('downloadEncrypted');
    const baseName = filename.replace(/\.[^/.]+$/, ''); // remove extension
    dl.download = baseName + '.encoded';
    dl.href = url;
    dl.style.display = 'inline';
  } else {
    document.getElementById('downloadEncrypted').style.display = 'none';
  }
});

document.getElementById('decryptBtn').addEventListener('click', async () => {
  const secret = document.getElementById('decryptSecret').value;
  const inputType = document.querySelector('input[name="decryptInputType"]:checked').value;
  let buffer;
  if (inputType === 'text') {
    const b64 = document.getElementById('payloadInput').value.trim();
    if (!b64) { alert('Enter base64 payload'); return; }
    buffer = fromBase64(b64);
  } else {
    const fileInput = document.getElementById('decryptFileInput');
    if (!fileInput.files[0]) { alert('Choose an encrypted file'); return; }
    buffer = await fileInput.files[0].arrayBuffer();
  }
  try {
    const { plaintext, filename } = await decryptPayload(buffer, secret);
    const blob = new Blob([new Uint8Array(plaintext)], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const dl = document.getElementById('downloadLink');
    dl.href = url;
    dl.download = filename;
    dl.textContent = 'Download ' + filename;
    dl.style.display = 'inline';

    // Attempt to render decrypted text if it's textual
    const decryptedTextArea = document.getElementById('decryptedTextArea');
    const copyBtn = document.getElementById('copyTextBtn');
    const bytes = new Uint8Array(plaintext);
    let text = null;
    try {
      text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch {
      text = null;
    }
    if (text !== null) {
      decryptedTextArea.value = text;
      copyBtn.style.display = 'inline';
    } else {
      decryptedTextArea.value = '';
      copyBtn.style.display = 'none';
    }
  } catch (e) {
    alert('Decrypt failed: ' + e.message);
  }
});
