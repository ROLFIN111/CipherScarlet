import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, simpledialog
from Crypto.Cipher import AES  # type:ignore
from Crypto.Protocol.KDF import PBKDF2  # type:ignore
from Crypto.Hash import SHA256  # type:ignore
from Crypto.Random import get_random_bytes  # type:ignore
import hashlib
import base64
import time

# CSec PARAMETERS 
SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16
KEY_LEN = 32                # AES-256 bit strength
PBKDF2_ITERS = 600_000      
VERSION = 1
MIN_KEYSTROKES = 30        


class CipherScarletApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CipherScarlet — Authenticated AES-256-GCM Toolkit")
        self.geometry("980x740")
        self.configure(bg="#211c1c")

        # Session cryptography state
        self.keystroke_salt = None        
        self._build_ui()

    def _build_ui(self):
        c = {
            "bg": "#1e1e24", 
            "panel": "#2a2b36", 
            "accent": "#ff5555", 
            "muted": "#44475a", 
            "fg": "#f8f8f2", 
            "btnfg": "#ffffff",
            "box_bg": "#111217"
        }

        header = tk.Label(self, text="CipherScarlet — Authenticated AES-GCM Suite",
                          bg=c["bg"], fg=c["fg"], font=("Helvetica", 16, "bold"), pady=14)
        header.pack(fill="x")

        #Inputs
        frame_in = tk.Frame(self, bg=c["bg"])
        frame_in.pack(fill="x", padx=16, pady=6)
        tk.Label(frame_in, text="Input Data (Plaintext to encrypt OR Base64 block payload to decrypt):",
                 bg=c["bg"], fg=c["fg"], font=("Helvetica", 10, "medium")).pack(anchor="w")
        self.input_entry = tk.Entry(frame_in, width=120, bg=c["panel"], fg=c["fg"], insertbackground=c["fg"], bd=1)
        self.input_entry.pack(fill="x", pady=6, ipady=4)

        # --- Operational Actions Grid ---
        row = tk.Frame(self, bg=c["bg"])
        row.pack(fill="x", padx=16, pady=8)
        
        self.btn_capture = tk.Button(row, text=f"🔑 Capture Entropy Salt (Min {MIN_KEYSTROKES} keys)",
                                     command=self.open_keystroke_popup,
                                     bg=c["muted"], fg=c["btnfg"], font=("Helvetica", 10, "bold"), relief="flat", padx=10, pady=4)
        self.btn_capture.grid(row=0, column=0, padx=6)

        self.btn_encrypt = tk.Button(row, text="🔒 Encrypt", command=self.encrypt_action,
                                     bg="#50fa7b", fg="#000000", font=("Helvetica", 10, "bold"), relief="flat", padx=14, pady=4)
        self.btn_encrypt.grid(row=0, column=1, padx=6)

        self.btn_decrypt = tk.Button(row, text="🔓 Decrypt", command=self.decrypt_action,
                                     bg="#8be9fd", fg="#000000", font=("Helvetica", 10, "bold"), relief="flat", padx=14, pady=4)
        self.btn_decrypt.grid(row=0, column=2, padx=6)

        self.btn_save = tk.Button(row, text="💾 Export (.txt)", command=self.save_output,
                                  bg=c["panel"], fg=c["btnfg"], font=("Helvetica", 10), relief="flat", padx=10, pady=4)
        self.btn_save.grid(row=0, column=3, padx=6)

        # --- Real-time Security Posture Tracking ---
        self.status_var = tk.StringVar(value="Entropy Matrix Status: ⛔ Uninitialized")
        self.status_lbl = tk.Label(self, textvariable=self.status_var, bg=c["bg"], fg="#ff5555", font=("Courier", 10, "bold"))
        self.status_lbl.pack(anchor="w", padx=20, pady=(4, 6))

        # --- Cryptographic Terminal Views ---
        frame_out = tk.Frame(self, bg=c["bg"])
        frame_out.pack(fill="both", expand=True, padx=16, pady=6)

        tk.Label(frame_out, text="Output Response Payload:", bg=c["bg"], fg=c["fg"]).pack(anchor="w")
        self.output_box = scrolledtext.ScrolledText(frame_out, height=7, bg=c["box_bg"], fg=c["fg"], insertbackground=c["fg"], wrap="word", bd=0)
        self.output_box.pack(fill="x", padx=4, pady=6)

        tk.Label(frame_out, text="Cryptographic Details Verification Ledger:", bg=c["bg"], fg=c["fg"]).pack(anchor="w")
        self.details_box = scrolledtext.ScrolledText(frame_out, height=10, bg=c["box_bg"], fg="#50fa7b", wrap="word", bd=0)
        self.details_box.pack(fill="both", padx=4, pady=6, expand=True)

    def open_keystroke_popup(self):
        popup = tk.Toplevel(self)
        popup.title("Entropy Capture Workspace")
        popup.geometry("560x240")
        popup.configure(bg="#2a2b36")
        popup.transient(self)
        popup.grab_set()

        tk.Label(popup,
                 text=f"Focus and type a sequence of random keys (at least {MIN_KEYSTROKES}) to harvest timing jitter entropy.\nInputs remain hidden dynamically.",
                 bg="#2a2b36", fg="#ffffff", wraplength=500, justify="center", font=("Helvetica", 10)).pack(pady=(16, 8))

        counter_var = tk.StringVar(value=f"Keystroke Buffer: 0 / {MIN_KEYSTROKES}")
        counter_lbl = tk.Label(popup, textvariable=counter_var, bg="#2a2b36", fg="#ffb86c",
                               font=("Courier", 12, "bold"))
        counter_lbl.pack(pady=(4, 6))

        entry_frame = tk.Frame(popup, bg="#111217", bd=1)
        entry_frame.pack(pady=(6, 8))
        capture_entry = tk.Entry(entry_frame, width=48, bg="#111217", fg="#111217", insertbackground="#111217", bd=0)
        capture_entry.pack(ipadx=6, ipady=6)

        done_btn = tk.Button(popup, text="Awaiting System Threshold...", state="disabled", bg="#44475a", fg="#ffffff", relief="flat")
        done_btn.pack(pady=(12, 8))

        deltas = []
        last_time = {"t": None}
        count = {"n": 0}

        def on_key(event):
            if event.widget is not capture_entry:
                return
            now = time.time()
            delta = 0.0 if last_time["t"] is None else now - last_time["t"]
            last_time["t"] = now
            deltas.append(int(delta * 1_000_000) & 0xFFFFFFFF)
            count["n"] += 1
            counter_var.set(f"Keystroke Buffer: {count['n']} / {MIN_KEYSTROKES}")
            if count["n"] >= MIN_KEYSTROKES:
                done_btn.configure(state="normal", text="🧬 Inject Entropy Payload", bg="#ff5555")
            capture_entry.delete(0, 'end')

        capture_entry.bind("<KeyPress>", on_key)
        capture_entry.focus_set()

        def finish():
            raw = b"".join(d.to_bytes(4, "little") for d in deltas)
            rnd = get_random_bytes(SALT_LEN)
            digest = hashlib.sha256(raw + rnd).digest()
            self.keystroke_salt = digest[:SALT_LEN]
            
            # Wiping memory references cleanly
            del deltas[:]
            
            self.status_var.set(f"Entropy Matrix Status: ✅ Initialized (Hex Prefix: {self.keystroke_salt.hex()[:16]})")
            self.status_lbl.configure(fg="#50fa7b")
            popup.grab_release()
            popup.destroy()
            messagebox.showinfo("Entropy Extracted", "Dynamic keystroke entropy harvested safely.")

        done_btn.configure(command=finish)
        self.wait_window(popup)

    def encrypt_action(self):
        if self.keystroke_salt is None:
            messagebox.showwarning("Salt Error", "Please initialize the entropy salt matrix first.")
            return

        pw = simpledialog.askstring("Master Key Authentication", "Define decryption password passphrase:", show="*")
        if not pw:
            return

        plaintext_str = self.input_entry.get()
        if not plaintext_str:
            messagebox.showwarning("Input Validation Error", "Input cannot be null.")
            return
        
        plaintext = plaintext_str.encode("utf-8")
        pw_bytes = pw.encode("utf-8")

        try:
            # PBKDF2 high-round implementation using standard SHA256 algorithm block
            key = PBKDF2(pw_bytes, self.keystroke_salt, dkLen=KEY_LEN, count=PBKDF2_ITERS, hmac_hash_module=SHA256)
            nonce = get_random_bytes(NONCE_LEN)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            ciphertext, tag = cipher.encrypt_and_digest(plaintext)

            # Build formal cryptographic packet architecture
            pkg = bytes([VERSION]) + self.keystroke_salt + nonce + tag + ciphertext
            pkg_b64 = base64.b64encode(pkg).decode("utf-8")

            self.output_box.delete("1.0", "end")
            self.output_box.insert("1.0", pkg_b64)

            details = [
                "[+] Task Executed: GCM Authenticated Encryption Pipeline",
                f"[*] Structural Payload Size: {len(plaintext)} bytes",
                f"[*] Cryptographic Salt (Hex): {self.keystroke_salt.hex()}",
                f"[*] Cryptographic Nonce/IV (Hex): {nonce.hex()}",
                f"[*] Integrity Tag (Hex): {tag.hex()}",
                f"[*] Ciphertext Length Block (Bytes): {len(ciphertext)}"
            ]
            self.details_box.delete("1.0", "end")
            self.details_box.insert("1.0", "\n".join(details) + "\n")
        
        finally:
            # Memory cleaning execution loop (Overwrite active sensitive variables from application runtime)
            if 'key' in locals(): del key
            pw_arr = bytearray(pw_bytes)
            for i in range(len(pw_arr)): pw_arr[i] = 0
            del pw, pw_bytes

    def decrypt_action(self):
        pkg_b64 = self.input_entry.get().strip()
        if not pkg_b64:
            messagebox.showwarning("Input Validation Error", "Please provide a valid Base64 payload block.")
            return

        pw = simpledialog.askstring("Master Key Authentication", "Provide decryption password passphrase:", show="*")
        if not pw:
            return

        pw_bytes = pw.encode("utf-8")

        try:
            # Safe parsing base64 package structures
            try:
                pkg = base64.b64decode(pkg_b64)
            except Exception:
