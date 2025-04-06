import os
import hashlib
import base64

def clear_screen() -> None:
    os.system('cls' if os.name == 'nt' else 'clear')

def print_home_screen() -> None:
    red = "\033[31m"
    blue = "\033[34m"
    reset = "\033[0m"
    ascii_art = f"""{red}
██████ ╗██╗      █████╗ ████████╗███████╗     █████╗ ██╗   ██╗████████╗ ██████╗ 
██╔════╝██║     ██╔══██╗╚══██╔══╝██╔════╝    ██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗
██║     ██║     ███████║   ██║   ███████╗    ███████║██║   ██║   ██║   ██║   ██║
██║     ██║     ██╔══██║   ██║   ╚════██║    ██╔══██║██║   ██║   ██║   ██║   ██║
╚██████╗███████╗██║  ██║   ██║   ███████║    ██║  ██║╚██████╔╝   ██║   ╚██████╔╝
 ╚═════╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝    ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ 

    ██╗  ██╗███████╗██╗   ██╗     ██████╗██╗██████╗ ██╗  ██╗███████╗██████╗     
    ██║ ██╔╝██╔════╝╚██╗ ██╔╝    ██╔════╝██║██╔══██╗██║  ██║██╔════╝██╔══██╗    
    █████╔╝ █████╗   ╚████╔╝     ██║     ██║██████╔╝███████║█████╗  ██████╔╝    
    ██╔═██╗ ██╔══╝    ╚██╔╝      ██║     ██║██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗    
    ██║  ██╗███████╗   ██║       ╚██████╗██║██║     ██║  ██║███████╗██║  ██║    
    ╚═╝  ╚═╝╚══════╝   ╚═╝        ╚═════╝╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝{reset}"""
    print(ascii_art)
    print(blue + "C L A T S   A U T O K E Y   C I P H E R" + reset, end=" ")
    print(red + "Version 1.00" + reset)
    print("By Joshua M Clatney - Ethical Pentesting Enthusiast")
    print("-----------------------------------------------------")
    print("Options:")
    print("1. Encrypt text")
    print("2. Decrypt text\n")

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

def encrypt(text: str, user_keyword: str) -> str:
    derived_key = expand_keyword(user_keyword)
    nonce = generate_nonce(16)
    intermediate_text = encrypt_autokey(text, user_keyword)
    intermediate_bytes = intermediate_text.encode('ascii', errors='ignore')
    xored = xor_with_derived_stream(intermediate_bytes, derived_key, nonce)
    combined = nonce + xored
    return base64.b64encode(combined).decode('utf-8')

def decrypt(cipher_text_b64: str, user_keyword: str) -> str:
    derived_key = expand_keyword(user_keyword)
    combined = base64.b64decode(cipher_text_b64)
    nonce = combined[:16]
    xored_data = combined[16:]
    intermediate_bytes = xor_with_derived_stream(xored_data, derived_key, nonce)
    intermediate_text = intermediate_bytes.decode('ascii', errors='ignore')
    return decrypt_autokey(intermediate_text, user_keyword)

def process_encrypt() -> None:
    text = input("Enter text to encrypt: ")
    keyword = input("Enter keyword: ").strip()

    if not any(c.isalpha() for c in text):
        print("Error: Text must contain at least one alphabetic character.")
        return

    if not keyword.isalpha():
        print("Error: Keyword must consist of alphabetic characters only.")
        return

    result = encrypt(text, keyword)
    print("\nEncrypted text:", result)

def process_decrypt() -> None:
    text = input("Enter text to decrypt: ")
    keyword = input("Enter keyword: ").strip()

    if not text:
        print("Error: Must provide ciphertext to decrypt.")
        return

    if not keyword.isalpha():
        print("Error: Keyword must consist of alphabetic characters only.")
        return

    try:
        result = decrypt(text, keyword)
        print("\nDecrypted text:", result)
    except Exception as e:
        print("Error during decryption:", e)

def main() -> None:
    while True:
        clear_screen()
        print_home_screen()
        choice = input("Choose an option (1 or 2): ").strip()
        if choice == '1':
            process_encrypt()
        elif choice == '2':
            process_decrypt()
        else:
            print("Invalid option. Please choose 1 or 2.")

        input("\nPress Enter to return to the home screen...")

if __name__ == "__main__":
    main()