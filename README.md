# Secure Chat (SM4 + HMAC)

A simple two-terminal secure chat prototype using:
- **SM4 (CBC mode)** for encryption
- **HMAC-SHA256** for integrity and authentication
- **TCP sockets** on localhost

---

## Requirements

- Python 3.9+
- Packages from `requirements.txt`

Install dependencies:
```bash
pip install -r requirements.txt
```

If you want to keep the installation isolated, create a virtual environment and install the requirements from inside it:

### macOS / Linux
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### Windows
```bash
python -m venv .venv
.venv\\Scripts\\activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

After activation, use `python -m pip` so the packages are installed into the virtual environment.

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