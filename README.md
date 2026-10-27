# CipherScarlet

CipherScarlet is a production-grade, desktop cryptographic tool written in Python. It implements high-security file and message encryption using **AES-256 in Galois/Counter Mode (GCM)**. 

To mitigate traditional brute-force, dictionary, and automated credential-stuffing attacks, CipherScarlet uses a custom **biometric/behavioral entropy capture engine** that derives cryptographically secure salt vectors based on unique hardware-level human typing cadences.

---

## Cryptographic & Security Architecture

The tool follows strict cryptographic engineering standards to guarantee both **Confidentiality** and **Authenticity**:

* **Authenticated Encryption:** Employs **AES-256-GCM** via `PyCryptodome`. The Galois/Counter Mode provides high-performance symmetric encryption alongside built-in integrity checking via a 16-byte authentication tag.
* **Behavioral Key Derivation:** Captures microsecond deltas (`time.time()`) between consecutive user keystrokes ($\ge 30$ keystrokes). These hardware-bound timestate intervals are packed, appended to an entropy buffer via `Crypto.Random`, and hashed using `SHA-256` to create a truly unpredictable, mathematically unique 16-byte session salt.
* **Heavy Key Stretching:** Stretches the user's password utilizing **PBKDF2** over **200,000 iterations** combined with the behavioral salt matrix to neutralize dictionary attacks.
* **Secure Formatting (Packed Payloads):** Outputs are safely structured as portable, single-string Base64 packages with a standardized structural preamble:
  $$\text{Payload} = \text{Version (1 Byte)} \parallel \text{Salt (16 Bytes)} \parallel \text{Nonce (12 Bytes)} \parallel \text{Tag (16 Bytes)} \parallel \text{Ciphertext}$$

---

## User Interface & Workspace Layout

The framework utilizes an explicit, clean GUI dashboard constructed via Python's native `tkinter` libraries:

* **Dark High-Contrast Theme:** Optimized for low-light environment audits with a focused dark-red cybersecurity-themed design layout.
* **Blind Entry Shield:** The keystroke entropy capture dialog processes inputs invisibly inside a hidden frame layer. Keystroke inputs are monitored strictly by execution timers without rendering any textual indicators to the screen, providing native over-the-shoulder protection against shoulder-surfing attacks.
* **Dedicated Diagnostic Outlets:** Separates raw encrypted payloads from underlying structural details (hex values of salts, nonces, and runtime tag verifications) to keep forensic workflows organized.

---

## Getting Started

### Prerequisites
Ensure your local machine has Python 3.8 or newer installed.

### Installation
1. Clone the project repository from your terminal:
   ```bash
   git clone https://github.com
   cd CipherScarlet
   ```

2. Install the standard dependencies via pip:
   ```bash
   pip install pycryptodome
   ```

### How To Run
Launch the GUI application workspace from your terminal:
```bash
python main.py
```

---

## Step-by-Step Usage Guide

### 1. Encrypting Plaintext
1. Enter your target secret message in the **Input** entry field.
2. Click **Capture Keystroke Salt**. A secure popup panel will open.
3. Click inside the collection frame box and type at least 30 random characters at a natural typing cadence to generate your dynamic salt. Click **Done**.
4. Click the main **Encrypt** button, input your chosen master password when prompted, and hit enter.
5. The unified, portable Base64 string will populate the **Output** area, while architectural metadata logs populate the **Details** frame.
6. Click **Save Output+Details (.txt)** to export your forensic file data locally.

### 2. Decrypting a Package
1. Paste the entire packed Base64 payload back into the top **Input** field.
2. Click **Decrypt**.
3. Input the exact master password when prompted.
4. The system automatically reads the binary version block, separates the embedded salt, nonce, and tag elements, verifies authenticity via GCM authentication checks, and extracts your original cleartext safely into the **Output** block.

---

## Secure Engineering Compliance
* **Memory Best Practices:** Session parameters are bound strictly to isolated runtime instances, keeping variables safe from leaking across persistent windows.
* **Error Handling:** Implements explicit verification tagging. Altered, corrupt, or truncated base64 payloads instantly trigger validation failures rather than failing silently or causing memory overflows.
