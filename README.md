# CipherChat (SM4 + HMAC)

A simple two-terminal secure chat prototype using:
- **SM4 (CBC mode)** for encryption
- **HMAC-SHA256** for integrity and authentication
- **TCP sockets** on localhost

---

## Requirements

- Python 3.9+

Install the dependency:
```bash
pip install -r requirements.txt
```

That's it — only `gmssl` is needed.

---

## How to Run

Open two terminals.

### Terminal 1 (Sender)
```bash
python main.py
```

Choose:
- mode: `sender`
- host: default `127.0.0.1`
- port: default `5000`
- username
- auto-generated password (copy this)

### Terminal 2 (Receiver)
```bash
python main.py
```

Choose:
- mode: `receiver`
- same host/port
- username
- **paste the same password**

---

## Quit Command
Type:
```
/quit
```
to end the session gracefully.

---

## Security Notes
- SM4 uses **CBC mode**, so a random IV is generated per message.
- Each packet includes **HMAC-SHA256** for tamper detection.
- The password is turned into keys with PBKDF2.

This is a prototype for learning and not intended for production use.

---

## Documentation Site

A static documentation site is in `web/` — built with Next.js + Tailwind CSS. It covers the protocol, cryptography, usage, and security notes above.

```bash
cd web
npm install
npm run build
```

The build script copies the output into `docs/` (ready for GitHub Pages).