#!/usr/bin/env python3
"""
VaultCipher CLI - Cryptographic Toolkit
Features: AES-256-GCM | RSA-2048 | SHA Hashing | Password Strength Analysis
Usage: python vaultcipher_cli.py [command] [options]

Requirements:
    pip install cryptography
"""

import argparse
import base64
import hashlib
import math
import os
import re
import string
import sys
from pathlib import Path

# --- AES (via cryptography library) ---
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

BANNER = """
╔══════════════════════════════════════════╗
║          V A U L T C I P H E R          ║
║   AES-256 · RSA-2048 · SHA · Toolkit    ║
╚══════════════════════════════════════════╝
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

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
