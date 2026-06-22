# 🔐 VaultCipher

> **AES-256-GCM + RSA-2048 + SHA Hashing + Digital Signatures**  
> Python CLI + Offline Browser UI — No server. No cloud. Pure cryptography.

![Made with Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat&logo=python&logoColor=white)
![Crypto](https://img.shields.io/badge/Crypto-AES--256--GCM%20%7C%20RSA--2048%20%7C%20SHA-00f5c4?style=flat)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat)

---

## 📌 What is VaultCipher?

VaultCipher is a comprehensive cryptographic toolkit that lets you **encrypt, decrypt, hash, sign, and verify** using battle-tested algorithms:

- **AES-256-GCM** — Symmetric authenticated encryption used by governments and banks
- **RSA-2048/4096** — Asymmetric encryption behind HTTPS, SSH, and secure communications
- **RSA-PSS** — Digital signatures for message authentication and non-repudiation
- **SHA-256/384/512** — Cryptographic hashing for integrity verification
- **Password Strength Analysis** — Entropy-based password scoring with pattern detection

It comes with two interfaces:
- A **Python CLI** for terminal-based cryptographic operations
- A **fully offline Browser UI** — open `index.html` and it just works, no internet required

> ⚠️ Built for **educational purposes**. Demonstrates real cryptographic principles used in production systems.

---

## 📁 Project Structure

```
VaultCipher/
├── index.html            # Web UI (open in any browser)
├── forge.min.js          # Crypto library for browser (offline)
├── vaultcipher_cli.py    # Python CLI tool
├── requirements.txt      # Python dependencies
├── SECURITY.md           # Security policy & best practices
├── keys/                 # Generated RSA key pairs (gitignored)
│   ├── private_key.pem
│   └── public_key.pem
└── README.md
```

---

## 🚀 Getting Started

### Prerequisites

- Python 3.8+
- pip

### Install dependencies

```bash
pip install -r requirements.txt
```

---

## 💻 CLI Usage

### AES-256-GCM — Symmetric Encryption

**Encrypt a message:**
```bash
python vaultcipher_cli.py aes-encrypt --text "your secret message" --password "yourpassword"
```

**Decrypt a message:**
```bash
python vaultcipher_cli.py aes-decrypt --payload "BASE64_CIPHERTEXT_HERE" --password "yourpassword"
```

---

### RSA-2048 — Asymmetric Encryption

**Generate a key pair:**
```bash
python vaultcipher_cli.py rsa-keygen --bits 2048 --output ./keys
```
> Use `--bits 4096` for extra security (slower generation)

**Encrypt with public key:**
```bash
python vaultcipher_cli.py rsa-encrypt --text "hello" --pubkey ./keys/public_key.pem
```

**Decrypt with private key:**
```bash
python vaultcipher_cli.py rsa-decrypt --payload "BASE64_CIPHERTEXT_HERE" --privkey ./keys/private_key.pem
```

---

### ✍️ RSA-PSS — Digital Signatures

**Sign a message:**
```bash
python vaultcipher_cli.py rsa-sign --message "I approve this transaction" --privkey ./keys/private_key.pem
```

**Verify a signature:**
```bash
python vaultcipher_cli.py rsa-verify --message "I approve this transaction" --signature "BASE64_SIG" --pubkey ./keys/public_key.pem
```

> Digital signatures prove that a message was created by a known sender and was not altered in transit.

---

### 🔑 SHA Hashing

**Hash text (SHA-256 by default):**
```bash
python vaultcipher_cli.py hash-text --text "hello world"
```

**Hash with a different algorithm:**
```bash
python vaultcipher_cli.py hash-text --text "hello world" --algorithm sha512
```

**Hash a file (streaming, memory-efficient):**
```bash
python vaultcipher_cli.py hash-file --file ./README.md --algorithm sha256
```

> Supported algorithms: `sha256`, `sha384`, `sha512`, `md5`

---

### 🔒 Password Strength Analysis

```bash
python vaultcipher_cli.py password-strength --password "MyS3cur3P@ssw0rd!"
```

Output includes:
- Score (0–100) with visual bar
- Rating (CRITICAL / WEAK / FAIR / GOOD / STRONG)
- Entropy estimation in bits
- Actionable feedback on how to improve

---

## 🌐 Web UI Usage

1. Make sure `index.html` and `forge.min.js` are in the **same folder**
2. Double-click `index.html` to open in your browser
3. No internet connection required — everything runs locally

| Tab | Features |
|-----|----------|
| **AES** | Encrypt/decrypt with password + live strength meter |
| **RSA** | Generate keys, encrypt/decrypt, sign/verify messages |
| **HASHING** | SHA-256/384/512/SHA-1 digest computation |
| **HOW IT WORKS** | Cryptographic concepts explained |

---

## 🔬 How It Works — The Cryptography

### AES-256-GCM (Symmetric)

AES (Advanced Encryption Standard) in GCM (Galois/Counter Mode) is the gold standard for symmetric encryption. The same key encrypts and decrypts.

| Parameter | Value |
|-----------|-------|
| Key Size | 256 bits |
| Mode | GCM (Authenticated Encryption) |
| KDF | PBKDF2-SHA256 |
| Iterations | 480,000 |
| Salt | 16 bytes (random per operation) |
| Nonce | 12 bytes (random per operation) |

**Step-by-step encryption flow:**
1. Generate a random 16-byte **salt**
2. Derive a 256-bit key from your password using **PBKDF2-SHA256** (480k iterations)
3. Generate a random 12-byte **nonce**
4. Encrypt the message using **AES-GCM** → produces ciphertext + 16-byte auth tag
5. Output: `base64(salt + nonce + ciphertext + tag)`

**Why PBKDF2?** Raw passwords are weak keys. PBKDF2 stretches your password into a proper 256-bit key and makes brute-force attacks computationally expensive.

**Why GCM?** GCM provides *authenticated encryption* — if anyone tampers with the ciphertext, decryption fails. You get both **confidentiality** and **integrity**.

---

### RSA-2048 with OAEP (Asymmetric)

RSA uses a mathematically linked key pair. What the public key encrypts, only the private key can decrypt — and vice versa.

| Parameter | Value |
|-----------|-------|
| Key Sizes | 2048 / 4096 bits |
| Padding | OAEP-SHA256 |
| Public Exponent | 65537 |
| Format | PEM (PKCS#1) |
| Max Message Size | ~190 bytes (2048-bit key) |

**The math behind RSA:** Security relies on the fact that multiplying two large prime numbers is easy, but factoring the result back into those primes is computationally infeasible at this scale.

**Why OAEP?** Raw/textbook RSA has known vulnerabilities. OAEP (Optimal Asymmetric Encryption Padding) adds randomness and structure that defeats these attacks.

**Real-world pattern (Hybrid Encryption):** RSA alone can only encrypt small payloads. In production systems, AES encrypts the actual data, and RSA encrypts the AES key. This is how HTTPS works.

---

### RSA-PSS (Digital Signatures)

RSA-PSS (Probabilistic Signature Scheme) provides **authentication** and **non-repudiation**:

| Parameter | Value |
|-----------|-------|
| Scheme | PSS (Probabilistic Signature Scheme) |
| Hash | SHA-256 |
| Salt Length | Maximum |
| Use Case | Message authentication, code signing |

**How it works:**
1. Hash the message with SHA-256
2. Sign the hash with the private key using PSS padding
3. Anyone with the public key can verify the signature
4. If the message is altered, verification fails

---

### Cryptographic Hashing (SHA)

| Algorithm | Digest Size | Status |
|-----------|-------------|--------|
| SHA-256 | 256 bits (64 hex chars) | ✅ Recommended |
| SHA-384 | 384 bits (96 hex chars) | ✅ Secure |
| SHA-512 | 512 bits (128 hex chars) | ✅ Secure |
| SHA-1 | 160 bits (40 hex chars) | ⚠️ Legacy |
| MD5 | 128 bits (32 hex chars) | ❌ Broken |

---

## 🛡️ Security Concepts Covered

| Concept | Description |
|---------|-------------|
| **Salt** | Random data added to password before hashing — defeats rainbow table attacks |
| **Nonce** | Used exactly once per encryption — ensures same message encrypts differently every time |
| **PBKDF2** | Deliberately slow key derivation — makes brute-force attacks expensive |
| **Authenticated Encryption** | GCM's auth tag detects any tampering with ciphertext |
| **Public/Private Key Pair** | Foundation of all modern secure communication |
| **Digital Signatures** | RSA-PSS proves message authenticity and detects tampering |
| **PEM Format** | Standard text format for storing and sharing RSA keys |
| **OAEP Padding** | Secure padding scheme that hardens RSA against known attacks |
| **PSS Padding** | Probabilistic signature padding — more secure than PKCS#1 v1.5 |
| **Entropy** | Measure of randomness/unpredictability in a password or key |

---

## 📦 Dependencies

| Tool | Purpose |
|------|---------|
| `cryptography` (Python) | AES-GCM, RSA, PBKDF2, PSS signatures for CLI |
| `forge.min.js` (Browser) | Full crypto library for offline web UI |

---

## ⚠️ Important Notes

- **Never commit your `keys/` folder to GitHub** — your private key must stay private
- RSA is limited to ~190 bytes per encryption with 2048-bit keys — use AES for large data
- This project is for **educational use** — for production systems, use established libraries and follow security auditing practices
- All cryptographic operations run **locally** — no data is sent anywhere
- See [SECURITY.md](SECURITY.md) for detailed security best practices

---

## 👤 Author

Built by **[H8RSH100](https://github.com/H8rsh100)** — CS/IT Engineering Student  
Part of a cybersecurity portfolio series.

---

## 📄 License

MIT License — free to use, modify, and learn from.
