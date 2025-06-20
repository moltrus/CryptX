# CryptX - File Encryption Utility

CryptX is a terminal-based file encryption and decryption tool written in Python. It uses AES encryption with password-derived keys to secure individual files or entire directories. Every encrypted file is tagged with a unique identifier and checked against integrity using HMAC.

## Requirements

- Python 3.6+
- Dependencies:
    - `cryptography>=3.4.0`

## Core Functions

### File Operations
- Single file encryption/decryption
- Batch directory processing
- Automatic operation detection based on file signatures

### Command Reference
| Command | Function |
|---------|----------|
| `[filepath]` | Process file/directory |
| `exit` | Terminate application |
| `cls` | Clear terminal |

## Security Implementation

### Cryptographic Components

| Component | Implementation |
|-----------|----------------|
| Key Derivation | PBKDF2-HMAC-SHA256 |
| Encryption Algorithm | AES-256-CFB |
| Data Integrity | HMAC Authentication |
| Secure Erasure | Multi-pass random overwrite |

### Security Parameters
- Iteration Count: 100,000
- Salt Size: 16 bytes
- Key Size: 32 bytes
- IV Size: 16 bytes

### Technical Details
- Algorithm: AES in CFB mode
- Key Generation: PBKDF2-SHA256 with 100,000 iterations
- Random Elements: 16-byte salt and IV per file
- File Identification: 6-character alphanumeric tag in filename
- Data Protection: HMAC-SHA256 for integrity verification
- File Format: `[seed][salt][iv][encrypted_data][hmac]`
- Secure Cleanup: Original files overwritten with random data
