# 🛡️ Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest (main branch) | ✅ Yes |

## Responsible Disclosure

If you discover a security vulnerability in VaultCipher, please follow responsible disclosure practices:

1. **Do NOT** open a public GitHub issue for security vulnerabilities
2. Email the maintainer or open a private security advisory on GitHub
3. Provide a detailed description of the vulnerability and steps to reproduce

## Security Best Practices for Users

### Key Management
- **Never commit private keys** to version control — `keys/` is gitignored by default
- Store private keys in a secure, access-controlled location
- Use 4096-bit RSA keys for sensitive operations
- Rotate key pairs periodically

### Password Guidelines
- Use the built-in `password-strength` command to evaluate passwords before use
- Minimum 12 characters recommended for AES encryption passwords
- Mix uppercase, lowercase, digits, and special characters
- Avoid dictionary words and common patterns

### Encryption Practices
- Always use authenticated encryption (AES-GCM) over unauthenticated modes
- Never reuse nonces — VaultCipher generates random nonces per operation
- For large data, use AES-256-GCM (symmetric) rather than RSA (asymmetric)
- RSA-2048 is limited to ~190 bytes — use hybrid encryption for larger payloads

### Digital Signatures
- Use RSA-PSS (not PKCS#1 v1.5) for signing — VaultCipher uses PSS by default
- Always verify signatures before trusting message authenticity
- Keep signing keys (private keys) strictly confidential

### Hashing
- Use SHA-256 or SHA-512 for integrity checks — avoid MD5 and SHA-1 for security
- Hash verification should use constant-time comparison to prevent timing attacks

## Cryptographic Algorithms Used

| Algorithm | Purpose | Status |
|-----------|---------|--------|
| AES-256-GCM | Symmetric encryption | ✅ Industry standard |
| RSA-2048/4096 OAEP | Asymmetric encryption | ✅ Industry standard |
| RSA-PSS SHA-256 | Digital signatures | ✅ Industry standard |
| PBKDF2-SHA256 (480k iter) | Key derivation | ✅ OWASP recommended |
| SHA-256 / SHA-512 | Hashing | ✅ Industry standard |

## Disclaimer

VaultCipher is built for **educational purposes**. While it uses production-grade cryptographic algorithms, it has not undergone a formal security audit. For production systems, use established, audited cryptographic libraries and consult security professionals.
