# app.py
import os
import base64
import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import scrolledtext
from encryptor import encrypt_bytes, decrypt_bytes

ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

class EncryptApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("AES-128 Encryptor")
        self.geometry("900x600")

        # Password entry
        self.pw_label = ctk.CTkLabel(self, text="Password:")
        self.pw_label.pack(padx=16, pady=(12,0), anchor="w")
        self.password_entry = ctk.CTkEntry(self, placeholder_text="Enter password", show="*")
        self.password_entry.pack(fill="x", padx=16, pady=(0,8))

        # Text box
        self.txt_label = ctk.CTkLabel(self, text="Text (encrypt/decrypt):")
        self.txt_label.pack(padx=16, pady=(8,0), anchor="w")
        self.text_input = scrolledtext.ScrolledText(self, height=12)
        self.text_input.pack(fill="both", expand=True, padx=16, pady=(0,12))

        # Buttons area
        btn_frame = ctk.CTkFrame(self)
        btn_frame.pack(fill="x", padx=16, pady=12)
        enc_text_btn = ctk.CTkButton(btn_frame, text="Encrypt Text", command=self.encrypt_text)
        dec_text_btn = ctk.CTkButton(btn_frame, text="Decrypt Text", command=self.decrypt_text)
        enc_file_btn = ctk.CTkButton(btn_frame, text="Encrypt File", command=self.encrypt_file)
        dec_file_btn = ctk.CTkButton(btn_frame, text="Decrypt File", command=self.decrypt_file)
        enc_text_btn.grid(row=0, column=0, padx=8, pady=8)
        dec_text_btn.grid(row=0, column=1, padx=8, pady=8)
        enc_file_btn.grid(row=0, column=2, padx=8, pady=8)
        dec_file_btn.grid(row=0, column=3, padx=8, pady=8)

    def get_password(self):
        pw = self.password_entry.get()
        if not pw:
            messagebox.showwarning("Missing password", "Please enter a password first.")
            return None
        return pw

    def encrypt_text(self):
        pw = self.get_password()
        if not pw: return
        plaintext = self.text_input.get("1.0", tk.END).encode("utf-8")
        if not plaintext.strip():
            messagebox.showwarning("Empty", "Please type some text to encrypt.")
            return
        enc = encrypt_bytes(plaintext, pw, filename="")
        b64 = base64.b64encode(enc).decode("utf-8")
        self.text_input.delete("1.0", tk.END)
        self.text_input.insert(tk.END, b64)
        messagebox.showinfo("Encrypted", "Text encrypted. Base64 output shown in the box.")

    def decrypt_text(self):
        pw = self.get_password()
        if not pw: return
        b64 = self.text_input.get("1.0", tk.END).strip()
        if not b64:
            messagebox.showwarning("Empty", "Paste the Base64 ciphertext to decrypt.")
            return
        try:
            enc = base64.b64decode(b64)
            data, orig_name = decrypt_bytes(enc, pw)
            try:
                txt = data.decode("utf-8")
                self.text_input.delete("1.0", tk.END)
                self.text_input.insert(tk.END, txt)
            except UnicodeDecodeError:
                # binary data — show info and offer to save
                save_path = filedialog.asksaveasfilename(title="Save decrypted bytes", defaultextension="")
                if save_path:
                    with open(save_path, "wb") as f:
                        f.write(data)
                    messagebox.showinfo("Saved", f"Decrypted bytes saved to {save_path}")
                else:
                    messagebox.showinfo("Note", "Decryption succeeded but data is binary and wasn't saved.")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")

    def encrypt_file(self):
        pw = self.get_password()
        if not pw: return
        path = filedialog.askopenfilename(title="Select file to encrypt")
        if not path:
            return
        with open(path, "rb") as f:
            data = f.read()
        enc = encrypt_bytes(data, pw, filename=os.path.basename(path))
        out_path = path + ".enc"
        with open(out_path, "wb") as f:
            f.write(enc)
        messagebox.showinfo("Encrypted", f"Encrypted file saved to:\n{out_path}")

    def decrypt_file(self):
        pw = self.get_password()
        if not pw: return
        path = filedialog.askopenfilename(title="Select .enc file to decrypt", filetypes=[("Encrypted files","*.enc"),("All files","*.*")])
        if not path:
            return
        with open(path, "rb") as f:
            enc = f.read()
        try:
            data, orig_name = decrypt_bytes(enc, pw)
            suggested = orig_name if orig_name else os.path.splitext(os.path.basename(path))[0] + ".dec"
            save_path = filedialog.asksaveasfilename(initialfile=suggested, title="Save decrypted file as")
            if not save_path:
                return
            with open(save_path, "wb") as f:
                f.write(data)
            messagebox.showinfo("Done", f"Decrypted file saved to:\n{save_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")

if __name__ == "__main__":
    app = EncryptApp()
    app.mainloop()
