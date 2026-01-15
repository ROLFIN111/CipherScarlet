import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, simpledialog
from Crypto.Cipher import AES  # type:ignore
from Crypto.Protocol.KDF import PBKDF2  # type:ignore
from Crypto.Hash import SHA256  # type:ignore
from Crypto.Random import get_random_bytes  # type:ignore
import hashlib
import base64
import time

# ----- PARAMETERS -----
SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16
KEY_LEN = 32                # AES-256
PBKDF2_ITERS = 200_000
VERSION = 1
MIN_KEYSTROKES = 30        # minimum keystrokes required in popup


class CipherScarletApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CipherScarlet — AES-GCM")
        self.geometry("980x700")
        self.configure(bg="#331111")

        # session state
        self.keystroke_salt = None        # 16-byte salt created from keystrokes
        self._last_raw_keystroke_digest = None  # internal debug-only digest (optional)

        self._build_ui()

    def _build_ui(self):
        # color palette
        c = {"bg": "#3a0000", "panel": "#560000", "muted": "#7a1010", "fg": "#fff6f6", "btnfg": "#ffffff"}

        header = tk.Label(self, text="CipherScarlet — AES-GCM ",
                          bg=c["bg"], fg=c["fg"], font=("Helvetica", 16, "bold"), pady=10)
        header.pack(fill="x")

        # --- Input line ---
        frame_in = tk.Frame(self, bg=c["bg"])
        frame_in.pack(fill="x", padx=12, pady=6)
        tk.Label(frame_in, text="Input (plaintext to encrypt OR base64 package to decrypt):",
                 bg=c["bg"], fg=c["fg"]).pack(anchor="w")
        self.input_entry = tk.Entry(frame_in, width=120, bg=c["muted"], fg=c["fg"])
        self.input_entry.pack(fill="x", pady=6)

        # --- Buttons row ---
        row = tk.Frame(self, bg=c["bg"])
        row.pack(fill="x", padx=12, pady=6)
        self.btn_capture = tk.Button(row,
                                     text=f"Capture Keystroke Salt (min {MIN_KEYSTROKES})",
                                     command=self.open_keystroke_popup,
                                     bg=c["panel"], fg=c["btnfg"], width=34)
        self.btn_capture.grid(row=0, column=0, padx=6)

        self.btn_encrypt = tk.Button(row, text="Encrypt", command=self.encrypt_action,
                                     bg=c["muted"], fg=c["btnfg"], width=12)
        self.btn_encrypt.grid(row=0, column=1, padx=6)

        self.btn_decrypt = tk.Button(row, text="Decrypt", command=self.decrypt_action,
                                     bg=c["muted"], fg=c["btnfg"], width=12)
        self.btn_decrypt.grid(row=0, column=2, padx=6)

        self.btn_save = tk.Button(row, text="Save Output+Details (.txt)", command=self.save_output,
                                  bg=c["muted"], fg=c["btnfg"], width=24)
        self.btn_save.grid(row=0, column=3, padx=6)

        # --- Status ---
        self.status_var = tk.StringVar(value="Salt: ⛔ Not set")
        tk.Label(self, textvariable=self.status_var, bg=c["bg"], fg=c["fg"]).pack(anchor="w", padx=12, pady=(0, 6))

        # --- Output & Details ---
        frame_out = tk.Frame(self, bg=c["bg"])
        frame_out.pack(fill="both", expand=True, padx=12, pady=6)

        tk.Label(frame_out, text="Output (base64 package or plaintext result):", bg=c["bg"], fg=c["fg"]).pack(anchor="w")
        self.output_box = scrolledtext.ScrolledText(frame_out, height=8, bg="#220000", fg=c["fg"], wrap="word")
        self.output_box.pack(fill="x", padx=6, pady=6)

        tk.Label(frame_out, text="Details (salt/nonce/tag/length):", bg=c["bg"], fg=c["fg"]).pack(anchor="w")
        self.details_box = scrolledtext.ScrolledText(frame_out, height=12, bg="#220000", fg=c["fg"], wrap="word")
        self.details_box.pack(fill="both", padx=6, pady=6, expand=True)

    # ---------------- Keystroke popup (hidden entry) ----------------
    def open_keystroke_popup(self):
        popup = tk.Toplevel(self)
        popup.title(f"Keystroke Salt — type at least {MIN_KEYSTROKES} keys")
        popup.geometry("560x240")
        popup.configure(bg="#550000")
        popup.transient(self)
        popup.grab_set()

        tk.Label(popup,
                 text=(f"Click the box below to focus, then type at least {MIN_KEYSTROKES} random keys.\n"
                       "(Keystrokes will NOT be shown — only the counter.)"),
                 bg="#550000", fg="white", wraplength=520, justify="left").pack(pady=(12, 8))

        counter_var = tk.StringVar(value=f"Keystrokes: 0 / {MIN_KEYSTROKES}")
        counter_lbl = tk.Label(popup, textvariable=counter_var, bg="#550000", fg="white",
                               font=("Helvetica", 12, "bold"))
        counter_lbl.pack(pady=(6, 6))

        # Hidden entry field (keystrokes invisible)
        entry_frame = tk.Frame(popup, bg="#440000", bd=2, relief="sunken")
        entry_frame.pack(pady=(6, 8))
        capture_entry = tk.Entry(entry_frame, width=48, bg="#440000", fg="#440000", insertbackground="#440000")
        capture_entry.pack(ipadx=6, ipady=6)

        tk.Label(popup, text="Click inside the box, then type.", bg="#550000", fg="white").pack()

        done_btn = tk.Button(popup, text="Done (disabled)", state="disabled", bg="#771111", fg="white")
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
            counter_var.set(f"Keystrokes: {count['n']} / {MIN_KEYSTROKES}")
            if count["n"] >= MIN_KEYSTROKES:
                done_btn.configure(state="normal", text="Done")
            capture_entry.delete(0, 'end')

        capture_entry.bind("<KeyPress>", on_key)
        capture_entry.focus_set()

        def finish():
            raw = b"".join(d.to_bytes(4, "little") for d in deltas)
            rnd = get_random_bytes(SALT_LEN)
            digest = hashlib.sha256(raw + rnd).digest()
            self.keystroke_salt = digest[:SALT_LEN]
            self.status_var.set(f"Salt: ✅ Set (hex prefix {self.keystroke_salt.hex()[:16]}...)")
            popup.grab_release()
            popup.destroy()
            messagebox.showinfo("Salt created", "Keystroke salt created and stored for this session.")

        done_btn.configure(command=finish)
        self.wait_window(popup)

    # ---------------- Encryption ----------------
    def encrypt_action(self):
        if self.keystroke_salt is None:
            messagebox.showwarning("Salt missing", "Please capture keystroke salt before encryption.")
            return

        pw = simpledialog.askstring("Password", "Enter password to derive key:", show="*")
        if not pw:
            return

        plaintext = self.input_entry.get().encode("utf-8")
        if not plaintext:
            messagebox.showwarning("No input", "Enter plaintext first.")
            return

        key = PBKDF2(pw.encode("utf-8"), self.keystroke_salt, dkLen=KEY_LEN, count=PBKDF2_ITERS,
                     hmac_hash_module=SHA256)
        nonce = get_random_bytes(NONCE_LEN)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        pkg = bytes([VERSION]) + self.keystroke_salt + nonce + tag + ciphertext
        pkg_b64 = base64.b64encode(pkg).decode("utf-8")

        self.output_box.delete("1.0", "end")
        self.output_box.insert("1.0", pkg_b64)

        details = [
            "Operation: Encrypt",
            f"Plaintext length: {len(plaintext)} bytes",
            f"Salt (hex): {self.keystroke_salt.hex()}",
            f"Nonce (hex): {nonce.hex()}",
            f"Tag (hex): {tag.hex()}",
            f"Ciphertext length (bytes): {len(ciphertext)}"
        ]
        self.details_box.delete("1.0", "end")
        self.details_box.insert("1.0", "\n".join(details) + "\n")

    # ---------------- Decryption ----------------
    def decrypt_action(self):
        pkg_b64 = self.input_entry.get().strip()
        if not pkg_b64:
            messagebox.showwarning("No package", "Paste base64 package to decrypt.")
            return

        pw = simpledialog.askstring("Password", "Enter password to derive key:", show="*")
        if not pw:
            return

        try:
            pkg = base64.b64decode(pkg_b64)
            pos = 1
            salt = pkg[pos:pos + SALT_LEN]; pos += SALT_LEN
            nonce = pkg[pos:pos + NONCE_LEN]; pos += NONCE_LEN
            tag = pkg[pos:pos + TAG_LEN]; pos += TAG_LEN
            ciphertext = pkg[pos:]

            key = PBKDF2(pw.encode("utf-8"), salt, dkLen=KEY_LEN, count=PBKDF2_ITERS, hmac_hash_module=SHA256)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)

            self.output_box.delete("1.0", "end")
            self.output_box.insert("1.0", plaintext.decode("utf-8", errors="replace"))

            details = [
                "Operation: Decrypt",
                f"Recovered plaintext length: {len(plaintext)} bytes",
                f"Salt (hex): {salt.hex()}",
                f"Nonce (hex): {nonce.hex()}",
                f"Tag (hex): {tag.hex()}",
                f"Ciphertext length (bytes): {len(ciphertext)}"
            ]
            self.details_box.delete("1.0", "end")
            self.details_box.insert("1.0", "\n".join(details) + "\n")

        except Exception as e:
            messagebox.showerror("Decryption failed", f"Decryption/authentication failed: {e}")

    # ---------------- Save output ----------------
    def save_output(self):
        file = filedialog.asksaveasfilename(defaultextension=".txt",
                                            filetypes=[("Text files", "*.txt")],
                                            title="Save Output and Details as")
        if not file:
            return
        with open(file, "w", encoding="utf-8") as f:
            f.write("=== OUTPUT ===\n")
            f.write(self.output_box.get("1.0", "end").rstrip() + "\n\n")
            f.write("=== DETAILS ===\n")
            f.write(self.details_box.get("1.0", "end").rstrip() + "\n")
        messagebox.showinfo("Saved", f"Output and details saved to:\n{file}")


if __name__ == "__main__":
    app = CipherScarletApp()
    app.bind_all("<Control-e>", lambda e: app.encrypt_action())
    app.bind_all("<Control-d>", lambda e: app.decrypt_action())
    app.mainloop()
