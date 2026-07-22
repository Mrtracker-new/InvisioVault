<p align="center">
  <img src="frontend/public/InvisioVault.png" alt="InvisioVault" width="160"/>
</p>

<h1 align="center">InvisioVault</h1>

<p align="center">
  Hide files inside images. Create files that double as archives. Smuggle messages through QR codes.<br/>
  <strong>Steganography toolkit built with Python and React.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-3776ab?style=flat-square&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/react-19-61dafb?style=flat-square&logo=react&logoColor=black"/>
  <img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square"/>
  <br/><br/>
  <a href="https://invisio-vault.vercel.app">Live Demo</a>
</p>

---

## What It Does

**Steganography** — Hide a file or text inside an image by embedding data into the least-significant bits of each pixel. The output looks identical to the original. Supports PNG, JPEG, and BMP carriers with a capacity indicator so you know what fits.

**Polyglot Files** — Create a single file that works as two formats. Open it normally and it's an image. Rename to `.zip` and your hidden files appear. Works with any carrier type — images, PDFs, videos, audio. No manual zipping needed.

**QR Code Steganography** — Generate QR codes with a hidden payload baked into the URL fragment. Standard scanners see a normal link. InvisioVault recovers the secret. Survives screenshots, prints, and camera recapture.

All three modes support optional password-protected encryption.

---

## Quick Start

**Windows** — just run `run.bat`.

**Everything else:**

```bash
# Backend
cd backend && pip install -r requirements.txt && python app.py

# Frontend (new terminal)
cd frontend && npm install && npm run dev
```

Open [localhost:5173](http://localhost:5173).

---

## Security

| | |
|---|---|
| **Encryption** | Fernet (AES-128-CBC + HMAC-SHA256), PBKDF2 at 480k iterations, AES-256 for polyglot ZIPs |
| **Validation** | Magic-byte verification, Pillow structural parsing, 100 MP pixel cap |
| **Protection** | Rate limiting, path traversal prevention, CSP/HSTS headers, auto temp-file cleanup |

---

## Tech Stack

**Backend** — Flask, Gunicorn, Pillow, cryptography, segno, zxing-cpp

**Frontend** — React 19, Vite, Axios

---

## Origin Story

This was my first-ever repo. The original code was *ambitious*. I came back, learned cryptography properly, and rebuilt it from scratch. If you're a beginner: keep shipping. The rough early code is proof you're growing.

---

<p align="center">
  <strong>Built by <a href="https://rolan-rnr.netlify.app/">Rolan</a></strong><br/>
  <a href="mailto:rolanlobo901@gmail.com">rolanlobo901@gmail.com</a> · <a href="https://github.com/Mrtracker-new">GitHub</a>
</p>

<p align="center"><sub>MIT License — use it, fork it, build something weird with it.</sub></p>
