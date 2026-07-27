# CipherChat 🔐

> A minimal, terminal-based secure chat prototype using **SM4 encryption** and **HMAC authentication**.

[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg?style=flat-square)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg?style=flat-square)](LICENSE)

CipherChat is a lightweight, two-terminal chat application designed as a learning prototype for Chinese cryptographic standards. It demonstrates how **SM4** (China's national block cipher) and **HMAC-SHA256** can be combined in a real-time messaging context using Python.

---

## Table of Contents

- [Features](#features)
- [Why SM4?](#why-sm4)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Project Structure](#project-structure)
- [Security Architecture](#security-architecture)
- [Documentation Site](#documentation-site)
- [Contributing](#contributing)
- [License](#license)

---

## Features

| Feature | Description |
|---------|-------------|
| **SM4-CBC Encryption** | Per-message random IV for confidentiality |
| **HMAC-SHA256** | Message integrity and authentication |
| **PBKDF2 Key Derivation** | Password-based key strengthening |
| **TCP Socket Transport** | Localhost two-party chat |
| **Graceful Quit** | `/quit` command to end session cleanly |

---

## Why SM4?

SM4 is China's national cryptographic standard ([GB/T 32907-2016](https://www.chinesestandard.net/pdfs/English/GBT32907-2016-English.pdf)). It is widely used in Chinese government, financial, and telecommunications systems. Using SM4 here instead of AES provides exposure to an algorithm that plays a central role in one of the world's largest digital economies.

---

## Requirements

- Python 3.9+

Install the dependency:

```bash
pip install -r requirements.txt
```

That's it — only [`gmssl`](https://github.com/duanhongyi/gmssl) is needed.

---

## Quick Start

Open **two** terminals in the project root.

### 1. Start the Receiver

```bash
python main.py
```

When prompted:
- **mode**: `receiver`
- **host**: `127.0.0.1` (default)
- **port**: `5000` (default)
- **username**: choose any name
- **password**: auto-generated — **copy this**

### 2. Start the Sender

```bash
python main.py
```

When prompted:
- **mode**: `sender`
- **host / port**: same as receiver
- **username**: choose any name
- **password**: **paste the exact same password**

### 3. Chat!

Type messages freely. To end the session, type:

```
/quit
```

---

## Project Structure

```
CipherChat/
├── main.py              # Entry point (sender / receiver)
├── requirements.txt     # Python dependencies
├── web/                 # Next.js documentation site
│   ├── app/
│   ├── components/
│   └── build → ../docs/ # GitHub Pages ready output
└── docs/                # Static site output (auto-generated)
```

---

## Security Architecture

| Layer | Mechanism | Purpose |
|-------|-----------|---------|
| **Confidentiality** | SM4-CBC | Encrypts message payload |
| **Integrity** | HMAC-SHA256 | Detects tampering |
| **Key Derivation** | PBKDF2-HMAC-SHA256 | Derives keys from user password |
| **Randomization** | Random IV per message | Prevents pattern analysis |

> ⚠️ **Disclaimer:** This is an educational prototype for learning purposes. It is **not** intended for production use or real-world secure communications.

---

## Documentation Site

A static documentation site lives in `web/` — built with Next.js + Tailwind CSS. It covers the protocol, cryptography, usage, and security notes in more detail.

```bash
cd web
npm install
npm run build
```

The build script copies the output into `docs/` (ready for GitHub Pages).

---

## Contributing

Contributions are welcome! Feel free to open an issue or submit a pull request.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/awesome-thing`)
3. Commit your changes (`git commit -m 'Add awesome thing'`)
4. Push to the branch (`git push origin feature/awesome-thing`)
5. Open a Pull Request

---

## License

This project is licensed under the [MIT License](LICENSE).
