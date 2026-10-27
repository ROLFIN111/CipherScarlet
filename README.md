# CipherScarlet 

CipherScarlet is an advanced, GUI-based cryptographic application that implements high-grade file and text encryption using **AES-256 in GCM (Galois/Counter Mode)**. It mitigates traditional password vulnerabilities by implementing a dynamic, behavior-based keystroke entropy engine.

## Key Features:
* **Authenticated Encryption:** Uses AES-256-GCM via PyCryptodome to ensure both data confidentiality and cryptographic integrity.
* **Biometric Salt Generation:** Captures real-time keystroke dynamics (requiring $\ge$ 30 unique strokes) to derive a highly complex, hardware-unique salt value.
* **Secure Key Derivation:** Implements PBKDF2 to stretch passwords securely before encryption mapping.
* **Modern GUI Workspace:** Built on Python's UI libraries for clean, intuitive key management and file processing.

## Prerequisites & Installation

Ensure you have Python 3.8+ installed, then clone the repository and install the dependencies:

```bash
git clone https://github.com
cd CipherScarlet
pip install -r requirements.txt
```

*Note: Requires `pycryptodome` for cryptographic operations.*

## Usage :
1. Run `python main.py` to launch the dashboard.
2. Enter your master password in the terminal prompt while typing at a natural cadence (the engine requires 30 strokes to build the behavioral salt matrix).
3. Select your target file to generate a `.enc` authenticated payload.
