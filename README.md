[![GitHub Pages](https://img.shields.io/badge/GitHub%20Pages-Published-brightgreen?style=for-the-badge)](https://rishprsi.github.io/Simple_Encrypt/)

# GitHub Pages Deployment for Simple_Encrypt

This project hosts a minimal client-side Simple_Encrypt encryptor on GitHub Pages. It uses the Web Crypto API to perform AES-256-GCM encryption on text or files in the browser, with an optional expiry header. The app can download encrypted files and upload encrypted files to decrypt.

## What’s included

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
