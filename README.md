[![GitHub Pages](https://img.shields.io/badge/GitHub%20Pages-Published-brightgreen?style=for-the-badge)](https://rishprsi.github.io/Simple_Encrypt/)

# GitHub Pages Deployment for Simple_Encrypt

This project hosts a minimal client-side Simple_Encrypt encryptor on GitHub Pages. It uses the Web Crypto API to perform AES-256-GCM encryption on text or files in the browser, with an optional expiry header. The app can download encrypted files and upload encrypted files to decrypt.

## Description

[![Live Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-brightgreen?style=for-the-badge)](https://rishprsi.github.io/Simple_Encrypt/)
[![AES-256-GCM](https://img.shields.io/badge/Crypto-AES--256--GCM-blue?style=for-the-badge)](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
[![Client-Side](https://img.shields.io/badge/Runtime-Browser%20Only-orange?style=for-the-badge)](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)

Simple_Encrypt is a browser-first encryption workspace that locks text and files with AES-256-GCM, optional expiry metadata, and zero server dependencies, so you can share sensitive content without handing it to a backend.

## Motivation

I built Simple_Encrypt after too many moments where I wanted to send a quick note or file safely, but every tool I reached for demanded accounts, uploads, or server trust. I wanted something that felt instant and private, where the encryption happens entirely in the browser and I can watch the data stay on my machine. This project is my answer to that friction: a focused, no-excuses encryptor that keeps control in the user's hands and still feels polished enough to share.

## Quick Start

1. Open the live site: <https://rishprsi.github.io/Simple_Encrypt/>
2. Paste text or select a file, enter a passphrase, and click Encrypt.
3. Download the encrypted output or upload it later to decrypt.

## Usage

- Encrypt text: paste content, set a passphrase, optionally set an expiry header, and generate encrypted output for sharing.
- Encrypt files: upload a file to produce an encrypted download that can be stored or shared securely.
- Decrypt text: paste encrypted payloads to restore the original content in the browser.
- Decrypt files: upload encrypted files to recover originals with the same passphrase.
- Optional expiry header: embed a lightweight expiry hint in the encrypted payload for receivers who want time-bound context.
- Client-only workflow: all cryptography runs locally via Web Crypto; no server-side secrets or uploads.

## Contributing

- docs/index.html: modern, minimal UI for encryption/decryption
- docs/js/secret.js: client-side logic for derive-key, encrypt, decrypt
- docs/README.md: deployment guide for GitHub Pages, plus local testing tips

## Deployment steps

1. Ensure you push the docs folder to your GitHub repository.
2. In GitHub, go to Settings -> Pages.
   - Source: Branch: main (or master), Folder: /docs
3. Access the page at https://<your-username>.github.io/<repo-name>/

## Local testing

- Serve docs locally: `cd docs && python3 -m http.server 8000`
- Open <http://localhost:8000/index.html>

## Notes

- This is client-side only; no server-side secrets.
- For production, consider a separate, hardened deployment if you need server-side processing.
