#!/usr/bin/env python3
"""
VaultCipher CLI - Cryptographic Toolkit
Features: AES-256-GCM | RSA-2048 | SHA Hashing | Password Strength Analysis
          IoT Device Authentication | Sensor Data Integrity Chains
Usage: python vaultcipher_cli.py [command] [options]

Requirements:
    pip install cryptography
"""

import argparse
import base64
import hashlib
import json
import math
import os
import re
import string
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

# --- AES (via cryptography library) ---
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

# Ensure UTF-8 output on Windows
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

BANNER = """
+==========================================+
|          V A U L T C I P H E R          |
|   AES-256 . RSA-2048 . SHA . IoT Auth   |
+==========================================+
"""

# ─────────────────────────────────────────
# AES Utilities
# ─────────────────────────────────────────

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from a password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def aes_encrypt(plaintext: str, password: str) -> str:
    """
    Encrypt plaintext with AES-256-GCM.
    Returns base64-encoded string: salt(16) + nonce(12) + ciphertext
    """
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext.encode(), None)
    payload = base64.b64encode(salt + nonce + ct).decode()
    return payload


def aes_decrypt(payload: str, password: str) -> str:
    """
    Decrypt base64-encoded AES-256-GCM payload.
    Returns original plaintext.
    """
    raw = base64.b64decode(payload.encode())
    salt, nonce, ct = raw[:16], raw[16:28], raw[28:]
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ct, None)
    return plaintext.decode()


# ─────────────────────────────────────────
# RSA Utilities
# ─────────────────────────────────────────

def rsa_generate_keys(key_size: int = 2048, output_dir: str = "."):
    """Generate RSA key pair and save to PEM files."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    priv_path = Path(output_dir) / "private_key.pem"
    pub_path = Path(output_dir) / "public_key.pem"

    with open(priv_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(pub_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    return str(priv_path), str(pub_path)


def rsa_encrypt(plaintext: str, pub_key_path: str) -> str:
    """Encrypt a short message using RSA public key (OAEP padding)."""
    with open(pub_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
    ct = public_key.encrypt(
        plaintext.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ct).decode()


def rsa_decrypt(payload: str, priv_key_path: str) -> str:
    """Decrypt RSA-encrypted payload using private key."""
    with open(priv_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    ct = base64.b64decode(payload.encode())
    plaintext = private_key.decrypt(
        ct,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()


def rsa_sign(message: str, priv_key_path: str) -> str:
    """Sign a message using RSA-PSS with SHA-256. Returns base64-encoded signature."""
    with open(priv_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()


def rsa_verify(message: str, signature_b64: str, pub_key_path: str) -> bool:
    """Verify an RSA-PSS signature. Returns True if valid, raises on failure."""
    with open(pub_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
    sig_bytes = base64.b64decode(signature_b64.encode())
    try:
        public_key.verify(
            sig_bytes,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


# ─────────────────────────────────────────
# Hashing Utilities
# ─────────────────────────────────────────

def hash_text(text: str, algorithm: str = "sha256") -> str:
    """Compute the hash digest of a text string."""
    h = hashlib.new(algorithm)
    h.update(text.encode("utf-8"))
    return h.hexdigest()


def hash_file(filepath: str, algorithm: str = "sha256") -> str:
    """Compute the hash digest of a file (streaming, memory-efficient)."""
    h = hashlib.new(algorithm)
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {filepath}")
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


# ─────────────────────────────────────────
# Password Strength Analyzer
# ─────────────────────────────────────────

def analyze_password(password: str) -> dict:
    """
    Analyze password strength based on length, character diversity,
    entropy, and common pattern detection.
    Returns a dict with score (0-100), rating, and feedback.
    """
    score = 0
    feedback = []
    length = len(password)

    # Length scoring (up to 30 pts)
    if length >= 16:
        score += 30
    elif length >= 12:
        score += 25
    elif length >= 8:
        score += 15
    elif length >= 6:
        score += 8
    else:
        feedback.append("Too short — use at least 8 characters.")

    # Character class diversity (up to 30 pts)
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"[0-9]", password))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", password))
    classes = sum([has_lower, has_upper, has_digit, has_symbol])
    score += classes * 7
    if classes < 3:
        feedback.append("Mix uppercase, lowercase, digits, and symbols.")

    # Entropy estimation (up to 25 pts)
    charset_size = 0
    if has_lower:
        charset_size += 26
    if has_upper:
        charset_size += 26
    if has_digit:
        charset_size += 10
    if has_symbol:
        charset_size += 32
    if charset_size > 0 and length > 0:
        entropy = length * math.log2(charset_size)
        if entropy >= 60:
            score += 25
        elif entropy >= 40:
            score += 15
        elif entropy >= 28:
            score += 8
        else:
            feedback.append(f"Low entropy ({entropy:.0f} bits) — easy to brute-force.")
    else:
        feedback.append("Cannot compute entropy — empty password.")

    # Pattern penalties (deductions up to -15)
    common_patterns = [
        r"^(password|123456|qwerty|admin|letmein|welcome)",
        r"(.)\1{3,}",  # 4+ repeated chars
        r"(012|123|234|345|456|567|678|789|890)",  # sequential digits
        r"(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn)",  # sequential letters
    ]
    for pattern in common_patterns:
        if re.search(pattern, password, re.IGNORECASE):
            score -= 5
            feedback.append(f"Detected common pattern — avoid predictable sequences.")
            break

    score = max(0, min(100, score))

    if score >= 80:
        rating = "STRONG"
    elif score >= 60:
        rating = "GOOD"
    elif score >= 40:
        rating = "FAIR"
    elif score >= 20:
        rating = "WEAK"
    else:
        rating = "CRITICAL"

    if not feedback:
        feedback.append("Looks solid. Good password hygiene!")

    return {"score": score, "rating": rating, "entropy_bits": entropy if charset_size > 0 else 0, "feedback": feedback}


# ─────────────────────────────────────────
# IoT Device Authentication
# ─────────────────────────────────────────

DEVICES_DIR = Path("devices")


def _device_dir(device_id: str) -> Path:
    """Return the storage directory for a given device."""
    return DEVICES_DIR / device_id


def device_register(device_id: str, key_size: int = 2048) -> dict:
    """
    Register an IoT device: generate RSA keypair bound to the device ID
    and issue a signed device certificate.
    """
    dev_dir = _device_dir(device_id)
    dev_dir.mkdir(parents=True, exist_ok=True)

    # Generate device-specific RSA keypair
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=key_size, backend=default_backend()
    )
    public_key = private_key.public_key()

    # Save keys
    priv_path = dev_dir / "private_key.pem"
    pub_path = dev_dir / "public_key.pem"
    with open(priv_path, "wb") as f:
        f.write(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ))
    with open(pub_path, "wb") as f:
        f.write(public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    # Compute public key fingerprint
    pub_der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    fingerprint = "SHA256:" + hashlib.sha256(pub_der).hexdigest()

    # Build and sign the device certificate
    issued_at = datetime.now(timezone.utc).isoformat()
    cert_data = f"{device_id}|{fingerprint}|{issued_at}"
    signature = private_key.sign(
        cert_data.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    certificate = {
        "device_id": device_id,
        "public_key_fingerprint": fingerprint,
        "issued_at": issued_at,
        "key_size": key_size,
        "signature": base64.b64encode(signature).decode()
    }
    cert_path = dev_dir / "certificate.json"
    with open(cert_path, "w") as f:
        json.dump(certificate, f, indent=2)

    return certificate


def _load_device_keys(device_id: str):
    """Load a registered device's RSA key pair."""
    dev_dir = _device_dir(device_id)
    if not dev_dir.exists():
        raise FileNotFoundError(f"Device '{device_id}' is not registered.")

    with open(dev_dir / "private_key.pem", "rb") as f:
        priv = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    with open(dev_dir / "public_key.pem", "rb") as f:
        pub = serialization.load_pem_public_key(f.read(), backend=default_backend())
    return priv, pub


def device_encrypt(plaintext: str, target_device_id: str) -> str:
    """
    Hybrid RSA+AES encryption locked to a specific device.
    Payload format: base64( device_id_len(2B) | device_id | rsa_encrypted_aes_key(256B) | salt(16B) | nonce(12B) | ciphertext | tag(16B) )
    """
    _, pub = _load_device_keys(target_device_id)

    # Generate random AES key (not password-derived — true random)
    aes_key = os.urandom(32)
    salt = os.urandom(16)
    nonce = os.urandom(12)

    # RSA-OAEP encrypt the AES key with the device's public key
    encrypted_aes_key = pub.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # AES-256-GCM encrypt the plaintext, with device_id as AAD (authenticated)
    aesgcm = AESGCM(aes_key)
    ct = aesgcm.encrypt(nonce, plaintext.encode(), target_device_id.encode())

    # Pack payload with embedded device ID
    device_id_bytes = target_device_id.encode("utf-8")
    header = struct.pack(">H", len(device_id_bytes)) + device_id_bytes
    payload = header + encrypted_aes_key + salt + nonce + ct

    return base64.b64encode(payload).decode()


def device_decrypt(payload_b64: str, requesting_device_id: str) -> str:
    """
    Device-gated decryption: checks device ID match before decrypting.
    Rejects if the requesting device doesn't match the payload's target.
    """
    raw = base64.b64decode(payload_b64.encode())

    # Extract embedded device ID from payload header
    id_len = struct.unpack(">H", raw[:2])[0]
    target_device_id = raw[2:2 + id_len].decode("utf-8")

    # ── DEVICE IDENTITY GATE ──
    if requesting_device_id != target_device_id:
        raise PermissionError(
            f"ACCESS DENIED: Payload is locked to device '{target_device_id}'. "
            f"Requesting device '{requesting_device_id}' is not authorized."
        )

    priv, _ = _load_device_keys(requesting_device_id)

    # Determine RSA ciphertext length from key size
    key_size_bytes = priv.key_size // 8
    offset = 2 + id_len
    encrypted_aes_key = raw[offset:offset + key_size_bytes]
    offset += key_size_bytes
    _salt = raw[offset:offset + 16]  # salt stored but not needed for random-key mode
    offset += 16
    nonce = raw[offset:offset + 12]
    offset += 12
    ct = raw[offset:]

    # RSA-OAEP decrypt the AES key
    aes_key = priv.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # AES-GCM decrypt with device_id as AAD
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ct, target_device_id.encode())

    return plaintext.decode()


# ─────────────────────────────────────────
# Sensor Data Integrity Chain
# ─────────────────────────────────────────

def _chain_path(device_id: str) -> Path:
    return _device_dir(device_id) / "chain.json"


def _hash_entry(entry: dict) -> str:
    """Compute SHA-256 hash of a chain entry (excluding the hash and signature fields)."""
    hashable = {k: v for k, v in entry.items() if k not in ("hash", "signature")}
    canonical = json.dumps(hashable, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def sensor_init(device_id: str) -> dict:
    """Create a new sensor chain with a genesis block for a registered device."""
    dev_dir = _device_dir(device_id)
    if not dev_dir.exists():
        raise FileNotFoundError(f"Device '{device_id}' is not registered. Run device-register first.")

    priv, _ = _load_device_keys(device_id)

    genesis = {
        "index": 0,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "device_id": device_id,
        "reading": "GENESIS",
        "prev_hash": "0" * 64,
    }
    genesis["hash"] = _hash_entry(genesis)

    # Sign the genesis hash
    sig = priv.sign(
        genesis["hash"].encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    genesis["signature"] = base64.b64encode(sig).decode()

    chain = [genesis]
    with open(_chain_path(device_id), "w") as f:
        json.dump(chain, f, indent=2)

    return genesis


def sensor_push(device_id: str, reading: str) -> dict:
    """Append a new hash-chained, signed sensor reading."""
    chain_file = _chain_path(device_id)
    if not chain_file.exists():
        raise FileNotFoundError(f"No chain found for '{device_id}'. Run sensor-init first.")

    with open(chain_file, "r") as f:
        chain = json.load(f)

    priv, _ = _load_device_keys(device_id)
    prev = chain[-1]

    entry = {
        "index": prev["index"] + 1,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "device_id": device_id,
        "reading": reading,
        "prev_hash": prev["hash"],
    }
    entry["hash"] = _hash_entry(entry)

    sig = priv.sign(
        entry["hash"].encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    entry["signature"] = base64.b64encode(sig).decode()

    chain.append(entry)
    with open(chain_file, "w") as f:
        json.dump(chain, f, indent=2)

    return entry


def sensor_verify(device_id: str) -> dict:
    """
    Verify the full sensor chain integrity:
    1. Each hash is correctly computed
    2. Each prev_hash links to the actual previous entry
    3. Each RSA-PSS signature is valid
    4. No index gaps
    Returns: {valid: bool, entries: int, error: str|None, broken_at: int|None}
    """
    chain_file = _chain_path(device_id)
    if not chain_file.exists():
        raise FileNotFoundError(f"No chain found for '{device_id}'.")

    with open(chain_file, "r") as f:
        chain = json.load(f)

    _, pub = _load_device_keys(device_id)

    for i, entry in enumerate(chain):
        # Check index continuity
        if entry["index"] != i:
            return {"valid": False, "entries": len(chain), "error": f"Index gap: expected {i}, got {entry['index']}", "broken_at": i}

        # Recompute and verify hash
        expected_hash = _hash_entry(entry)
        if entry["hash"] != expected_hash:
            return {"valid": False, "entries": len(chain), "error": f"Hash mismatch at index {i}", "broken_at": i}

        # Verify prev_hash link (skip genesis)
        if i > 0 and entry["prev_hash"] != chain[i - 1]["hash"]:
            return {"valid": False, "entries": len(chain), "error": f"Broken link: entry {i} prev_hash doesn't match entry {i-1}", "broken_at": i}

        # Verify RSA-PSS signature
        try:
            sig_bytes = base64.b64decode(entry["signature"].encode())
            pub.verify(
                sig_bytes,
                entry["hash"].encode(),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
        except Exception:
            return {"valid": False, "entries": len(chain), "error": f"Invalid signature at index {i}", "broken_at": i}

    return {"valid": True, "entries": len(chain), "error": None, "broken_at": None}


# ─────────────────────────────────────────
# CLI Commands
# ─────────────────────────────────────────

def cmd_aes_encrypt(args):
    result = aes_encrypt(args.text, args.password)
    print(f"\n✅ Encrypted (AES-256-GCM):\n{result}\n")


def cmd_aes_decrypt(args):
    try:
        result = aes_decrypt(args.payload, args.password)
        print(f"\n✅ Decrypted:\n{result}\n")
    except Exception:
        print("\n❌ Decryption failed. Wrong password or corrupted payload.\n")


def cmd_rsa_keygen(args):
    priv, pub = rsa_generate_keys(key_size=args.bits, output_dir=args.output)
    print(f"\n✅ RSA-{args.bits} Key Pair Generated:")
    print(f"   Private Key → {priv}")
    print(f"   Public Key  → {pub}\n")


def cmd_rsa_encrypt(args):
    result = rsa_encrypt(args.text, args.pubkey)
    print(f"\n✅ RSA Encrypted:\n{result}\n")


def cmd_rsa_decrypt(args):
    try:
        result = rsa_decrypt(args.payload, args.privkey)
        print(f"\n✅ RSA Decrypted:\n{result}\n")
    except Exception as e:
        print(f"\n❌ RSA Decryption failed: {e}\n")


def cmd_rsa_sign(args):
    try:
        sig = rsa_sign(args.message, args.privkey)
        print(f"\n✍️  RSA-PSS Signature:\n{sig}\n")
    except Exception as e:
        print(f"\n❌ Signing failed: {e}\n")


def cmd_rsa_verify(args):
    try:
        valid = rsa_verify(args.message, args.signature, args.pubkey)
        if valid:
            print(f"\n✅ Signature is VALID — message is authentic and untampered.\n")
        else:
            print(f"\n❌ Signature is INVALID — message may have been tampered with.\n")
    except Exception as e:
        print(f"\n❌ Verification failed: {e}\n")


def cmd_hash_text(args):
    digest = hash_text(args.text, args.algorithm)
    print(f"\n🔑 {args.algorithm.upper()} Hash:\n{digest}\n")


def cmd_hash_file(args):
    try:
        digest = hash_file(args.file, args.algorithm)
        print(f"\n🔑 {args.algorithm.upper()} Hash of '{args.file}':\n{digest}\n")
    except FileNotFoundError as e:
        print(f"\n❌ {e}\n")


def cmd_password_strength(args):
    result = analyze_password(args.password)
    bar_length = 30
    filled = int(bar_length * result['score'] / 100)
    bar = '█' * filled + '░' * (bar_length - filled)

    colors = {'CRITICAL': '🔴', 'WEAK': '🟠', 'FAIR': '🟡', 'GOOD': '🟢', 'STRONG': '🟢'}
    icon = colors.get(result['rating'], '⚪')

    print(f"\n{icon} Password Strength: {result['rating']}")
    print(f"   Score: [{bar}] {result['score']}/100")
    print(f"   Entropy: ~{result['entropy_bits']:.0f} bits")
    print(f"   Feedback:")
    for tip in result['feedback']:
        print(f"     → {tip}")
    print()


def cmd_device_register(args):
    try:
        cert = device_register(args.device_id, args.bits)
        print(f"\n✅ Device '{args.device_id}' registered successfully!")
        print(f"   Fingerprint: {cert['public_key_fingerprint']}")
        print(f"   Issued at:   {cert['issued_at']}")
        print(f"   Key size:    {cert['key_size']}-bit RSA")
        print(f"   Keys saved:  devices/{args.device_id}/")
        print()
    except Exception as e:
        print(f"\n❌ Registration failed: {e}\n")


def cmd_device_encrypt(args):
    try:
        result = device_encrypt(args.text, args.device_id)
        print(f"\n🔒 Encrypted (device-bound to '{args.device_id}'):")
        print(f"{result}\n")
    except Exception as e:
        print(f"\n❌ Device encryption failed: {e}\n")


def cmd_device_decrypt(args):
    try:
        result = device_decrypt(args.payload, args.device_id)
        print(f"\n🔓 Device '{args.device_id}' authorized — decrypted:")
        print(f"{result}\n")
    except PermissionError as e:
        print(f"\n🚫 {e}\n")
    except Exception as e:
        print(f"\n❌ Device decryption failed: {e}\n")


def cmd_sensor_init(args):
    try:
        genesis = sensor_init(args.device_id)
        print(f"\n⛓️  Sensor chain initialized for '{args.device_id}'")
        print(f"   Genesis hash: {genesis['hash'][:32]}...")
        print(f"   Chain file:   devices/{args.device_id}/chain.json")
        print()
    except Exception as e:
        print(f"\n❌ Chain init failed: {e}\n")


def cmd_sensor_push(args):
    try:
        entry = sensor_push(args.device_id, args.reading)
        print(f"\n📡 Reading #{entry['index']} added to chain")
        print(f"   Data:      {entry['reading']}")
        print(f"   Hash:      {entry['hash'][:32]}...")
        print(f"   Prev hash: {entry['prev_hash'][:32]}...")
        print(f"   Signed:    ✅ RSA-PSS")
        print()
    except Exception as e:
        print(f"\n❌ Sensor push failed: {e}\n")


def cmd_sensor_verify(args):
    try:
        result = sensor_verify(args.device_id)
        if result["valid"]:
            print(f"\n✅ Chain VALID — {result['entries']} entries verified")
            print(f"   All hashes:     ✅ correct")
            print(f"   All links:      ✅ intact")
            print(f"   All signatures: ✅ authentic")
        else:
            print(f"\n❌ Chain BROKEN at entry #{result['broken_at']}")
            print(f"   Error: {result['error']}")
            print(f"   Entries checked: {result['entries']}")
        print()
    except Exception as e:
        print(f"\n❌ Verification failed: {e}\n")


# ─────────────────────────────────────────
# Main
# ─────────────────────────────────────────

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(
        prog="vaultcipher",
        description="VaultCipher - AES-256-GCM + RSA-2048 CLI Toolkit"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # aes-encrypt
    p1 = sub.add_parser("aes-encrypt", help="Encrypt text with AES-256-GCM")
    p1.add_argument("--text", required=True, help="Plaintext to encrypt")
    p1.add_argument("--password", required=True, help="Encryption password")
    p1.set_defaults(func=cmd_aes_encrypt)

    # aes-decrypt
    p2 = sub.add_parser("aes-decrypt", help="Decrypt AES-256-GCM ciphertext")
    p2.add_argument("--payload", required=True, help="Base64 encrypted payload")
    p2.add_argument("--password", required=True, help="Decryption password")
    p2.set_defaults(func=cmd_aes_decrypt)

    # rsa-keygen
    p3 = sub.add_parser("rsa-keygen", help="Generate RSA key pair")
    p3.add_argument("--bits", type=int, default=2048, choices=[2048, 4096], help="Key size (default: 2048)")
    p3.add_argument("--output", default=".", help="Output directory (default: current)")
    p3.set_defaults(func=cmd_rsa_keygen)

    # rsa-encrypt
    p4 = sub.add_parser("rsa-encrypt", help="Encrypt text with RSA public key")
    p4.add_argument("--text", required=True, help="Plaintext to encrypt")
    p4.add_argument("--pubkey", required=True, help="Path to public key PEM file")
    p4.set_defaults(func=cmd_rsa_encrypt)

    # rsa-decrypt
    p5 = sub.add_parser("rsa-decrypt", help="Decrypt with RSA private key")
    p5.add_argument("--payload", required=True, help="Base64 encrypted payload")
    p5.add_argument("--privkey", required=True, help="Path to private key PEM file")
    p5.set_defaults(func=cmd_rsa_decrypt)

    # hash-text
    p6 = sub.add_parser("hash-text", help="Compute SHA hash of text")
    p6.add_argument("--text", required=True, help="Text to hash")
    p6.add_argument("--algorithm", default="sha256", choices=["sha256", "sha512", "sha384", "md5"], help="Hash algorithm (default: sha256)")
    p6.set_defaults(func=cmd_hash_text)

    # hash-file
    p7 = sub.add_parser("hash-file", help="Compute SHA hash of a file")
    p7.add_argument("--file", required=True, help="Path to file")
    p7.add_argument("--algorithm", default="sha256", choices=["sha256", "sha512", "sha384", "md5"], help="Hash algorithm (default: sha256)")
    p7.set_defaults(func=cmd_hash_file)

    # password-strength
    p8 = sub.add_parser("password-strength", help="Analyze password strength")
    p8.add_argument("--password", required=True, help="Password to analyze")
    p8.set_defaults(func=cmd_password_strength)

    # rsa-sign
    p9 = sub.add_parser("rsa-sign", help="Sign a message with RSA-PSS")
    p9.add_argument("--message", required=True, help="Message to sign")
    p9.add_argument("--privkey", required=True, help="Path to private key PEM file")
    p9.set_defaults(func=cmd_rsa_sign)

    # rsa-verify
    p10 = sub.add_parser("rsa-verify", help="Verify an RSA-PSS signature")
    p10.add_argument("--message", required=True, help="Original message")
    p10.add_argument("--signature", required=True, help="Base64-encoded signature")
    p10.add_argument("--pubkey", required=True, help="Path to public key PEM file")
    p10.set_defaults(func=cmd_rsa_verify)

    # ── IoT Device Authentication ──

    # device-register
    p11 = sub.add_parser("device-register", help="Register an IoT device with unique ID")
    p11.add_argument("--device-id", required=True, help="Unique device identifier (e.g. sensor-42)")
    p11.add_argument("--bits", type=int, default=2048, choices=[2048, 4096], help="RSA key size (default: 2048)")
    p11.set_defaults(func=cmd_device_register)

    # device-encrypt
    p12 = sub.add_parser("device-encrypt", help="Encrypt data locked to a specific device")
    p12.add_argument("--text", required=True, help="Plaintext to encrypt")
    p12.add_argument("--device-id", required=True, help="Target device ID")
    p12.set_defaults(func=cmd_device_encrypt)

    # device-decrypt
    p13 = sub.add_parser("device-decrypt", help="Decrypt with device identity verification")
    p13.add_argument("--payload", required=True, help="Base64 device-encrypted payload")
    p13.add_argument("--device-id", required=True, help="Requesting device ID")
    p13.set_defaults(func=cmd_device_decrypt)

    # ── Sensor Data Integrity Chain ──

    # sensor-init
    p14 = sub.add_parser("sensor-init", help="Initialize sensor data chain for a device")
    p14.add_argument("--device-id", required=True, help="Device ID to create chain for")
    p14.set_defaults(func=cmd_sensor_init)

    # sensor-push
    p15 = sub.add_parser("sensor-push", help="Push a sensor reading to the integrity chain")
    p15.add_argument("--device-id", required=True, help="Device ID")
    p15.add_argument("--reading", required=True, help="Sensor reading data (e.g. 'temp=22.5')")
    p15.set_defaults(func=cmd_sensor_push)

    # sensor-verify
    p16 = sub.add_parser("sensor-verify", help="Verify sensor chain integrity")
    p16.add_argument("--device-id", required=True, help="Device ID to verify chain for")
    p16.set_defaults(func=cmd_sensor_verify)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
