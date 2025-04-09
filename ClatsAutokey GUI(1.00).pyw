import tkinter as tk
from tkinter import messagebox
import os
import hashlib

# ---------- Helper Functions (Encryption / Decryption) ----------

def expand_keyword(keyword: str, length: int = 64) -> bytes:
    keyword_bytes = keyword.encode('utf-8')
    derived = b""
    block = keyword_bytes
    while len(derived) < length:
        block = hashlib.sha256(block).digest()
        derived += block
    return derived[:length]

def generate_nonce(length: int = 16) -> bytes:
    return os.urandom(length)

def mix_autokey_char(prev_key_char: str, prev_plain_char: str) -> str:
    combo_val = (ord(prev_key_char) << 8) ^ ord(prev_plain_char)
    combo_bytes = combo_val.to_bytes(2, 'big')
    digest = hashlib.sha256(combo_bytes).digest()
    shift = digest[0] % 26
    return chr(ord('A') + shift)

def xor_with_derived_stream(data: bytes, derived_key: bytes, nonce: bytes) -> bytes:
    block_seed = derived_key + nonce
    out = bytearray(len(data))
    offset = 0
    counter = 0

    while offset < len(data):
        counter_bytes = counter.to_bytes(4, 'big')
        stream_key = hashlib.sha256(block_seed + counter_bytes).digest()
        for i in range(min(len(stream_key), len(data) - offset)):
            out[offset + i] = data[offset + i] ^ stream_key[i]
        offset += len(stream_key)
        counter += 1
    return bytes(out)

def encrypt_autokey(text: str, keyword: str) -> str:
    plaintext_alpha = [c for c in text if c.isalpha()]
    base_key = keyword.upper()
    extended_key = list(base_key)
    for i in range(len(plaintext_alpha) - len(base_key)):
        new_char = mix_autokey_char(extended_key[-1], plaintext_alpha[i + len(base_key) - 1].upper())
        extended_key.append(new_char)
    result = []
    extended_key_str = "".join(extended_key)
    letter_count = 0
    for char in text:
        if char.isalpha():
            shift = ord(extended_key_str[letter_count]) - ord('A')
            encrypted_char = chr((ord(char.upper()) - ord('A') + shift) % 26 + ord('A'))
            result.append(encrypted_char)
            letter_count += 1
        else:
            result.append(char)
    return "".join(result)

def decrypt_autokey(cipher_text: str, keyword: str) -> str:
    base_key = keyword.upper()
    extended_key = list(base_key)
    result = []
    letter_count = 0
    for char in cipher_text:
        if char.isalpha():
            shift = ord(extended_key[letter_count]) - ord('A')
            plain_char = chr((ord(char.upper()) - ord('A') - shift + 26) % 26 + ord('A'))
            result.append(plain_char)
            if len(extended_key) < letter_count + 2:
                new_char = mix_autokey_char(extended_key[-1], plain_char)
                extended_key.append(new_char)
            letter_count += 1
        else:
            result.append(char)
    return "".join(result)

def encode_to_uppercase_letters(data: bytes) -> str:
    encoded_chars = []
    for b in data:
        first = b // 26
        second = b % 26
        encoded_chars.append(chr(first + ord('A')))
        encoded_chars.append(chr(second + ord('A')))
    return ''.join(encoded_chars)

def decode_from_uppercase_letters(text: str) -> bytes:
    if len(text) % 2 != 0:
        raise ValueError("Encoded text length must be even.")
    decoded_bytes = bytearray()
    for i in range(0, len(text), 2):
        first = ord(text[i]) - ord('A')
        second = ord(text[i+1]) - ord('A')
        b = first * 26 + second
        decoded_bytes.append(b)
    return bytes(decoded_bytes)

def encrypt(text: str, user_keyword: str) -> str:
    derived_key = expand_keyword(user_keyword)
    nonce = generate_nonce(16)
    intermediate_text = encrypt_autokey(text, user_keyword)
    intermediate_bytes = intermediate_text.encode('ascii', errors='ignore')
    xored = xor_with_derived_stream(intermediate_bytes, derived_key, nonce)
    combined = nonce + xored
    return encode_to_uppercase_letters(combined)

def decrypt(cipher_text: str, user_keyword: str) -> str:
    derived_key = expand_keyword(user_keyword)
    combined = decode_from_uppercase_letters(cipher_text)
    nonce = combined[:16]
    xored_data = combined[16:]
    intermediate_bytes = xor_with_derived_stream(xored_data, derived_key, nonce)
    intermediate_text = intermediate_bytes.decode('ascii', errors='ignore')
    return decrypt_autokey(intermediate_text, user_keyword)

# ---------- Tkinter GUI Implementation ----------

class Application(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Clats Autokey Cipher GUI 1.00")
        # Widened geometry has been reduced for alignment with the ASCII art
        self.geometry("650x600")
        self.frames = {}
        for F in (HomeFrame, EncryptFrame, DecryptFrame):
            frame = F(parent=self, controller=self)
            self.frames[F] = frame
            frame.place(relwidth=1, relheight=1)
        self.show_frame(HomeFrame)
    
    def show_frame(self, container):
        frame = self.frames[container]
        frame.tkraise()

class HomeFrame(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        
        # ASCII Banner (without ANSI codes)
        ascii_art = (
            "██████ ╗██╗      █████╗ ████████╗███████╗     █████╗ ██╗   ██╗████████╗ ██████╗ \n"
            "██╔════╝██║     ██╔══██╗╚══██╔══╝██╔════╝    ██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗\n"
            "██║     ██║     ███████║   ██║   ███████╗    ███████║██║   ██║   ██║   ██║   ██║\n"
            "██║     ██║     ██╔══██║   ██║   ╚════██║    ██╔══██║██║   ██║   ██║   ██║   ██║\n"
            "╚██████╗███████╗██║  ██║   ██║   ███████║    ██║  ██║╚██████╔╝   ██║   ╚██████╔╝\n"
            " ╚═════╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝    ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ \n\n"
            "    ██╗  ██╗███████╗██╗   ██╗     ██████╗██╗██████╗ ██╗  ██╗███████╗██████╗     \n"
            "    ██║ ██╔╝██╔════╝╚██╗ ██╔╝    ██╔════╝██║██╔══██╗██║  ██║██╔════╝██╔══██╗    \n"
            "    █████╔╝ █████╗   ╚████╔╝     ██║     ██║██████╔╝███████║█████╗  ██████╔╝    \n"
            "    ██╔═██╗ ██╔══╝    ╚██╔╝      ██║     ██║██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗    \n"
            "    ██║  ██╗███████╗   ██║       ╚██████╗██║██║     ██║  ██║███████╗██║  ██║    \n"
            "    ╚═╝  ╚═╝╚══════╝   ╚═╝        ╚═════╝╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝"
        )
        banner_label = tk.Label(self, text=ascii_art, font=("Courier", 8), fg="red", justify="left")
        banner_label.pack(pady=10)

        # Title and Version
        title_frame = tk.Frame(self)
        title_frame.pack(pady=5)
        title_label = tk.Label(title_frame, text="C L A T S   A U T O K E Y   C I P H E R", 
                               font=("Courier", 12), fg="blue")
        title_label.pack(side="left", padx=5)
        version_label = tk.Label(title_frame, text="Version 1.00", font=("Courier", 12), fg="red")
        version_label.pack(side="left", padx=5)

        # Author and Divider
        author_label = tk.Label(self, text="By Joshua M Clatney - Ethical Pentesting Enthusiast", 
                                font=("Arial", 10), fg="black")
        author_label.pack(pady=5)
        divider = tk.Label(self, text="-----------------------------------------------------")
        divider.pack(pady=5)

        # Options and Buttons
        options_label = tk.Label(self, text="Options:", font=("Arial", 12, "bold"))
        options_label.pack(pady=5)

        btn_encrypt = tk.Button(self, text="Encrypt Text", width=20,
                                command=lambda: controller.show_frame(EncryptFrame))
        btn_encrypt.pack(pady=5)

        btn_decrypt = tk.Button(self, text="Decrypt Text", width=20,
                                command=lambda: controller.show_frame(DecryptFrame))
        btn_decrypt.pack(pady=5)

class EncryptFrame(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        
        header_label = tk.Label(self, text="Encrypt Text", font=("Arial", 14))
        header_label.pack(pady=10)
        
        self.text_label = tk.Label(self, text="Enter text to encrypt:")
        self.text_label.pack()
        self.text_input = tk.Text(self, height=5, width=60)
        self.text_input.pack(pady=5)
        
        self.key_label = tk.Label(self, text="Enter keyword (alphabetic only):")
        self.key_label.pack()
        self.key_entry = tk.Entry(self, width=60)
        self.key_entry.pack(pady=5)
        
        process_btn = tk.Button(self, text="Encrypt", command=self.process_encrypt)
        process_btn.pack(pady=10)
        
        result_label = tk.Label(self, text="Encrypted text:", font=("Arial", 12))
        result_label.pack()
        self.result_output = tk.Text(self, height=5, width=60, state="disabled")
        self.result_output.pack(pady=5)
        
        home_btn = tk.Button(self, text="Return Home", 
                             command=lambda: controller.show_frame(HomeFrame))
        home_btn.pack(pady=10)
    
    def process_encrypt(self):
        text = self.text_input.get("1.0", tk.END).strip()
        keyword = self.key_entry.get().strip()
        
        if not any(c.isalpha() for c in text):
            messagebox.showerror("Input Error", "Text must contain at least one alphabetic character.")
            return
        
        if not keyword.isalpha() or keyword == "":
            messagebox.showerror("Input Error", "Keyword must consist of alphabetic characters only.")
            return
        
        try:
            result = encrypt(text, keyword)
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))
            return
        
        self.result_output.config(state="normal")
        self.result_output.delete("1.0", tk.END)
        self.result_output.insert(tk.END, result)
        self.result_output.config(state="disabled")

class DecryptFrame(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        
        header_label = tk.Label(self, text="Decrypt Text", font=("Arial", 14))
        header_label.pack(pady=10)
        
        self.text_label = tk.Label(self, text="Enter text to decrypt:")
        self.text_label.pack()
        self.text_input = tk.Text(self, height=5, width=60)
        self.text_input.pack(pady=5)
        
        self.key_label = tk.Label(self, text="Enter keyword (alphabetic only):")
        self.key_label.pack()
        self.key_entry = tk.Entry(self, width=60)
        self.key_entry.pack(pady=5)
        
        process_btn = tk.Button(self, text="Decrypt", command=self.process_decrypt)
        process_btn.pack(pady=10)
        
        result_label = tk.Label(self, text="Decrypted text:", font=("Arial", 12))
        result_label.pack()
        self.result_output = tk.Text(self, height=5, width=60, state="disabled")
        self.result_output.pack(pady=5)
        
        home_btn = tk.Button(self, text="Return Home", 
                             command=lambda: controller.show_frame(HomeFrame))
        home_btn.pack(pady=10)
    
    def process_decrypt(self):
        text = self.text_input.get("1.0", tk.END).strip()
        keyword = self.key_entry.get().strip()
        
        if not text:
            messagebox.showerror("Input Error", "Please enter ciphertext to decrypt.")
            return
        
        if not keyword.isalpha() or keyword == "":
            messagebox.showerror("Input Error", "Keyword must consist of alphabetic characters only.")
            return
        
        try:
            result = decrypt(text, keyword)
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))
            return
        
        self.result_output.config(state="normal")
        self.result_output.delete("1.0", tk.END)
        self.result_output.insert(tk.END, result)
        self.result_output.config(state="disabled")

if __name__ == "__main__":
    app = Application()
    app.mainloop()