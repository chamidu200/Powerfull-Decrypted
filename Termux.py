#!/data/data/com.termux/files/usr/bin/env python3
import os
import subprocess
import time
import random
import multiprocessing
from concurrent.futures import ThreadPoolExecutor, as_completed
import string
import re
import secrets
import psutil
import json
import base64
import hashlib
from pyfiglet import Figlet
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from twofish import Twofish

console = Console()

def banner():
    f = Figlet(font='slant')
    banner_text = f.renderText('CryptoMaster')
    console.print(Panel(banner_text, style="bold cyan", title="CryptoMaster v9.0-Termux", border_style="green"))
    console.print("[italic yellow]Ultimate Multi-Pass Encryption & Cracking Suite for Termux[/italic yellow]\n")

# --- Key Generation with Multiple Passwords ---
def generate_multi_key(passwords, salt=None, iterations=500000):  # Reduced iterations for Termux performance
    """Generate a key from multiple passwords using PBKDF2HMAC."""
    if not passwords or any(not pwd.strip() for pwd in passwords):
        raise ValueError("All passwords must be non-empty!")
    if salt is None:
        salt = os.urandom(64)
    combined = "".join(passwords).encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=64,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    key = kdf.derive(combined)
    return key, salt

# --- Padding Utilities ---
def pad_data(data, block_size):
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding

def unpad_data(padded_data):
    padding_length = padded_data[-1]
    return padded_data[:-padding_length]

# --- RSA and ECC Key Generation ---
def generate_rsa_keys(key_size=4096):  # Reduced to 4096 for Termux performance
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def generate_ecc_key(curve=ec.SECP384R1()):  # Reduced curve size for Termux
    private_key = ec.generate_private_key(curve, default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

# --- Encryption Functions ---
def encrypt_data_ultimate(data, passwords, method="aes", rsa_key_path=None, ecc_key_path=None):
    try:
        if not data:
            raise ValueError("Data to encrypt cannot be empty!")
        if len(passwords) < 3:
            raise ValueError("At least 3 passwords are required!")
        key, salt = generate_multi_key(passwords)
        plaintext = data.encode()
        metadata = {
            "salt": base64.b64encode(salt).decode('utf-8'),
            "method": method.lower(),
            "nonce": None,
            "version": "9.0-Termux",
            "rsa_private_key": rsa_key_path,
            "rsa_public_key": None,
            "ecc_private_key": None,
            "ecc_public_key": None,
            "ecc_tag": None,
            "password_hashes": [base64.b64encode(hashlib.sha512(pwd.encode()).digest()).decode('utf-8') for pwd in passwords]
        }

        if method.lower() == "hybrid":
            return hybrid_encrypt(data, passwords)
        elif method.lower() == "layered":
            rsa_key_path = rsa_key_path or Prompt.ask("[bold green]RSA private key save path[/bold green]", default=os.path.join(os.getenv("HOME"), "layered_rsa_private_key.pem"))
            use_ecc = Confirm.ask("[bold green]Add ECC layer? (Optional)[/bold green]", default=False)
            if use_ecc:
                ecc_key_path = ecc_key_path or Prompt.ask("[bold green]ECC key save base path[/bold green]", default=os.path.join(os.getenv("HOME"), "layered_ecc_keys"))
                return layered_encrypt_with_ecc(data, passwords, rsa_key_path, ecc_key_path)
            return layered_encrypt(data, passwords, rsa_key_path)

        if method.lower() == "aes":
            aesgcm = AESGCM(key[:32])
            nonce = os.urandom(12)
            encrypted_data = aesgcm.encrypt(nonce, plaintext, None)
            metadata["nonce"] = base64.b64encode(nonce).decode('utf-8')
            console.print("[+] Encrypted with AES-256-GCM!", style="bold magenta")
        elif method.lower() == "chacha":
            chacha = ChaCha20Poly1305(key[:32])
            nonce = os.urandom(12)
            encrypted_data = chacha.encrypt(nonce, plaintext, None)
            metadata["nonce"] = base64.b64encode(nonce).decode('utf-8')
            console.print("[+] Encrypted with ChaCha20-Poly1305!", style="bold magenta")
        elif method.lower() == "fernet":
            fernet = Fernet(base64.urlsafe_b64encode(key[:32]))
            encrypted_data = fernet.encrypt(plaintext)
            console.print("[+] Encrypted with Fernet!", style="bold magenta")
        elif method.lower() == "rsa":
            rsa_key_path = rsa_key_path or os.path.join(os.getenv("HOME"), "rsa_private_key.pem")
            private_key, public_key = generate_rsa_keys()
            encrypted_data = public_key.encrypt(
                plaintext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA512()),
                    algorithm=hashes.SHA512(),
                    label=None
                )
            )
            key_password = Prompt.ask("[bold magenta]Enter a password to protect the RSA private key[/bold magenta]", password=True)
            with open(rsa_key_path, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.BestAvailableEncryption(key_password.encode())
                ))
            metadata["rsa_private_key"] = rsa_key_path
            metadata["rsa_public_key"] = f"{rsa_key_path.replace('.pem', '_public.pem')}"
            with open(metadata["rsa_public_key"], "wb") as f:
                f.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
            console.print(f"[+] Encrypted with RSA-4096! Private key saved to {rsa_key_path}", style="bold magenta")
        elif method.lower() == "ecc":
            ecc_key_path = ecc_key_path or os.path.join(os.getenv("HOME"), "ecc_keys")
            private_key, public_key = generate_ecc_key()
            shared_key = private_key.exchange(ec.ECDH(), public_key)
            derived_key = hashlib.sha512(shared_key).digest()[:32]
            nonce = os.urandom(12)
            cipher = Cipher(algorithms.AES(derived_key), modes.GCM(nonce), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(plaintext) + encryptor.finalize()
            key_password = Prompt.ask("[bold magenta]Enter a password to protect the ECC private key[/bold magenta]", password=True)
            with open(f"{ecc_key_path}_private.pem", "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.BestAvailableEncryption(key_password.encode())
                ))
            with open(f"{ecc_key_path}_public.pem", "wb") as f:
                f.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
            metadata["ecc_private_key"] = f"{ecc_key_path}_private.pem"
            metadata["ecc_public_key"] = f"{ecc_key_path}_public.pem"
            metadata["nonce"] = base64.b64encode(nonce).decode('utf-8')
            metadata["ecc_tag"] = base64.b64encode(encryptor.tag).decode('utf-8')
            console.print("[+] Encrypted with ECC (SECP384R1) + AES-GCM!", style="bold magenta")
        elif method.lower() == "tripledes":
            iv = os.urandom(8)
            cipher = Cipher(TripleDES(key[:24]), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            padded_data = pad_data(plaintext, 8)
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            metadata["nonce"] = base64.b64encode(iv).decode('utf-8')
            console.print("[+] Encrypted with Triple DES!", style="bold magenta")
        elif method.lower() == "twofish":
            tf = Twofish(key[:16])
            padded_data = pad_data(plaintext, 16)
            encrypted_data = b""
            for i in range(0, len(padded_data), 16):
                encrypted_data += tf.encrypt(padded_data[i:i+16])
            metadata["nonce"] = base64.b64encode(os.urandom(16)).decode('utf-8')
            console.print("[+] Encrypted with Twofish!", style="bold magenta")
        else:
            raise ValueError("Invalid encryption method!")

        h = hmac.HMAC(key, hashes.SHA512(), backend=default_backend())
        h.update(encrypted_data)
        metadata["hmac"] = base64.b64encode(h.finalize()).decode('utf-8')

        metadata_bytes = json.dumps(metadata).encode('utf-8')
        final_data = salt + b"|||" + metadata_bytes + b"|||" + encrypted_data
        console.print("[+] Encryption completed successfully!", style="bold green")
        return final_data
    except Exception as e:
        console.print(f"[-] Encryption failed: {e}", style="bold red")
        return None

def hybrid_encrypt(data, passwords):
    key, salt = generate_multi_key(passwords)
    aes_key = os.urandom(32)
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    encrypted_data = aesgcm.encrypt(nonce, data.encode(), None)
    
    private_key, public_key = generate_rsa_keys()
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA512()),
            algorithm=hashes.SHA512(),
            label=None
        )
    )
    
    rsa_key_path = os.path.join(os.getenv("HOME"), "hybrid_rsa_private_key.pem")
    rsa_public_key_path = os.path.join(os.getenv("HOME"), "hybrid_rsa_public_key.pem")
    key_password = Prompt.ask("[bold magenta]Enter a password to protect the RSA private key[/bold magenta]", password=True)
    with open(rsa_key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(key_password.encode())
        ))
    with open(rsa_public_key_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    
    metadata = {
        "salt": base64.b64encode(salt).decode('utf-8'),
        "method": "hybrid",
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "encrypted_key": base64.b64encode(encrypted_aes_key).decode('utf-8'),
        "private_key_file": rsa_key_path,
        "public_key_file": rsa_public_key_path,
        "version": "9.0-Termux",
        "password_hashes": [base64.b64encode(hashlib.sha512(pwd.encode()).digest()).decode('utf-8') for pwd in passwords]
    }
    
    h = hmac.HMAC(key, hashes.SHA512(), backend=default_backend())
    h.update(encrypted_data)
    metadata["hmac"] = base64.b64encode(h.finalize()).decode('utf-8')
    
    metadata_bytes = json.dumps(metadata).encode('utf-8')
    final_data = salt + b"|||" + metadata_bytes + b"|||" + encrypted_data
    console.print(f"[+] Data encrypted with Hybrid AES-256-GCM + RSA-4096! Private key saved to {rsa_key_path}", style="bold magenta")
    return final_data

def layered_encrypt(data, passwords, rsa_key_path=None):
    rsa_key_path = rsa_key_path or os.path.join(os.getenv("HOME"), "layered_rsa_private_key.pem")
    key, salt = generate_multi_key(passwords)
    plaintext = data.encode()
    metadata = {
        "salt": base64.b64encode(salt).decode('utf-8'),
        "layers": ["aes", "chacha", "twofish", "rsa"],
        "hmacs": [],
        "nonces": {},
        "rsa_private_key": rsa_key_path,
        "rsa_public_key": f"{rsa_key_path.replace('.pem', '_public.pem')}",
        "version": "9.0-Termux",
        "password_hashes": [base64.b64encode(hashlib.sha512(pwd.encode()).digest()).decode('utf-8') for pwd in passwords]
    }

    aes_key = hashlib.sha512(key + b"AES").digest()[:32]
    aesgcm = AESGCM(aes_key)
    nonce_aes = os.urandom(12)
    encrypted_data = aesgcm.encrypt(nonce_aes, plaintext, None)
    metadata["nonces"]["aes"] = base64.b64encode(nonce_aes).decode('utf-8')
    h = hmac.HMAC(key, hashes.SHA512(), backend=default_backend())
    h.update(encrypted_data)
    metadata["hmacs"].append(base64.b64encode(h.finalize()).decode('utf-8'))
    console.print("[+] Layer 1: Encrypted with AES-256-GCM!", style="bold magenta")

    chacha_key = hashlib.sha512(key + b"CHACHA").digest()[:32]
    chacha = ChaCha20Poly1305(chacha_key)
    nonce_chacha = os.urandom(12)
    encrypted_data = chacha.encrypt(nonce_chacha, encrypted_data, None)
    metadata["nonces"]["chacha"] = base64.b64encode(nonce_chacha).decode('utf-8')
    h = hmac.HMAC(key, hashes.SHA512(), backend=default_backend())
    h.update(encrypted_data)
    metadata["hmacs"].append(base64.b64encode(h.finalize()).decode('utf-8'))
    console.print("[+] Layer 2: Encrypted with ChaCha20-Poly1305!", style="bold magenta")

    twofish_key = hashlib.sha512(key + b"TWOFISH").digest()[:16]
    tf = Twofish(twofish_key)
    padded_data = pad_data(encrypted_data, 16)
    encrypted_data = b""
    for i in range(0, len(padded_data), 16):
        encrypted_data += tf.encrypt(padded_data[i:i+16])
    metadata["nonces"]["twofish"] = base64.b64encode(os.urandom(16)).decode('utf-8')
    h = hmac.HMAC(key, hashes.SHA512(), backend=default_backend())
    h.update(encrypted_data)
    metadata["hmacs"].append(base64.b64encode(h.finalize()).decode('utf-8'))
    console.print("[+] Layer 3: Encrypted with Twofish!", style="bold magenta")

    private_key, public_key = generate_rsa_keys()
    encrypted_data = public_key.encrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA512()),
            algorithm=hashes.SHA512(),
            label=None
        )
    )
    key_password = Prompt.ask("[bold magenta]Enter a password to protect the RSA private key[/bold magenta]", password=True)
    with open(rsa_key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(key_password.encode())
        ))
    with open(metadata["rsa_public_key"], "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    h = hmac.HMAC(key, hashes.SHA512(), backend=default_backend())
    h.update(encrypted_data)
    metadata["hmacs"].append(base64.b64encode(h.finalize()).decode('utf-8'))
    console.print(f"[+] Layer 4: Encrypted with RSA-4096! Private key saved to {rsa_key_path}", style="bold magenta")

    metadata_bytes = json.dumps(metadata).encode('utf-8')
    final_data = salt + b"|||" + metadata_bytes + b"|||" + encrypted_data
    console.print("[+] Multi-layer encryption completed!", style="bold green")
    return final_data

def layered_encrypt_with_ecc(data, passwords, rsa_key_path=None, ecc_key_path=None):
    rsa_key_path = rsa_key_path or os.path.join(os.getenv("HOME"), "layered_rsa_private_key.pem")
    ecc_key_path = ecc_key_path or os.path.join(os.getenv("HOME"), "layered_ecc_keys")
    key, salt = generate_multi_key(passwords)
    plaintext = data.encode()
    metadata = {
        "salt": base64.b64encode(salt).decode('utf-8'),
        "layers": ["aes", "chacha", "twofish", "ecc", "rsa"],
        "hmacs": [],
        "nonces": {},
        "rsa_private_key": rsa_key_path,
        "rsa_public_key": f"{rsa_key_path.replace('.pem', '_public.pem')}",
        "ecc_private_key": f"{ecc_key_path}_private.pem",
        "ecc_public_key": f"{ecc_key_path}_public.pem",
        "version": "9.0-Termux",
        "password_hashes": [base64.b64encode(hashlib.sha512(pwd.encode()).digest()).decode('utf-8') for pwd in passwords]
    }

    aes_key = hashlib.sha512(key + b"AES").digest()[:32]
    aesgcm = AESGCM(aes_key)
    nonce_aes = os.urandom(12)
    encrypted_data = aesgcm.encrypt(nonce_aes, plaintext, None)
    metadata["nonces"]["aes"] = base64.b64encode(nonce_aes).decode('utf-8')
    h = hmac.HMAC(key, hashes.SHA512(), backend=default_backend())
    h.update(encrypted_data)
    metadata["hmacs"].append(base64.b64encode(h.finalize()).decode('utf-8'))
    console.print("[+] Layer 1: Encrypted with AES-256-GCM!", style="bold magenta")

    chacha_key = hashlib.sha512(key + b"CHACHA").digest()[:32]
    chacha = ChaCha20Poly1305(chacha_key)
    nonce_chacha = os.urandom(12)
    encrypted_data = chacha.encrypt(nonce_chacha, encrypted_data, None)
    metadata["nonces"]["chacha"] = base64.b64encode(nonce_chacha).decode('utf-8')
    h = hmac.HMAC(key, hashes.SHA512(), backend=default_backend())
    h.update(encrypted_data)
    metadata["hmacs"].append(base64.b64encode(h.finalize()).decode('utf-8'))
    console.print("[+] Layer 2: Encrypted with ChaCha20-Poly1305!", style="bold magenta")

    twofish_key = hashlib.sha512(key + b"TWOFISH").digest()[:16]
    tf = Twofish(twofish_key)
    padded_data = pad_data(encrypted_data, 16)
    encrypted_data = b""
    for i in range(0, len(padded_data), 16):
        encrypted_data += tf.encrypt(padded_data[i:i+16])
    metadata["nonces"]["twofish"] = base64.b64encode(os.urandom(16)).decode('utf-8')
    h = hmac.HMAC(key, hashes.SHA512(), backend=default_backend())
    h.update(encrypted_data)
    metadata["hmacs"].append(base64.b64encode(h.finalize()).decode('utf-8'))
    console.print("[+] Layer 3: Encrypted with Twofish!", style="bold magenta")

    ecc_private_key, ecc_public_key = generate_ecc_key()
    shared_key = ecc_private_key.exchange(ec.ECDH(), ecc_public_key)
    derived_key = hashlib.sha512(shared_key).digest()[:32]
    nonce_ecc = os.urandom(12)
    cipher = Cipher(algorithms.AES(derived_key), modes.GCM(nonce_ecc), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(encrypted_data) + encryptor.finalize()
    ecc_key_password = Prompt.ask("[bold magenta]Enter a password to protect the ECC private key[/bold magenta]", password=True)
    with open(metadata["ecc_private_key"], "wb") as f:
        f.write(ecc_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(ecc_key_password.encode())
        ))
    with open(metadata["ecc_public_key"], "wb") as f:
        f.write(ecc_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    metadata["nonces"]["ecc"] = base64.b64encode(nonce_ecc).decode('utf-8')
    metadata["ecc_tag"] = base64.b64encode(encryptor.tag).decode('utf-8')
    h = hmac.HMAC(key, hashes.SHA512(), backend=default_backend())
    h.update(encrypted_data)
    metadata["hmacs"].append(base64.b64encode(h.finalize()).decode('utf-8'))
    console.print(f"[+] Layer 4: Encrypted with ECC (SECP384R1) + AES-GCM! Private key saved to {metadata['ecc_private_key']}", style="bold magenta")

    rsa_private_key, rsa_public_key = generate_rsa_keys()
    encrypted_data = rsa_public_key.encrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA512()),
            algorithm=hashes.SHA512(),
            label=None
        )
    )
    rsa_key_password = Prompt.ask("[bold magenta]Enter a password to protect the RSA private key[/bold magenta]", password=True)
    with open(rsa_key_path, "wb") as f:
        f.write(rsa_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(rsa_key_password.encode())
        ))
    with open(metadata["rsa_public_key"], "wb") as f:
        f.write(rsa_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    h = hmac.HMAC(key, hashes.SHA512(), backend=default_backend())
    h.update(encrypted_data)
    metadata["hmacs"].append(base64.b64encode(h.finalize()).decode('utf-8'))
    console.print(f"[+] Layer 5: Encrypted with RSA-4096! Private key saved to {rsa_key_path}", style="bold magenta")

    metadata_bytes = json.dumps(metadata).encode('utf-8')
    final_data = salt + b"|||" + metadata_bytes + b"|||" + encrypted_data
    console.print("[+] Multi-layer encryption with ECC completed!", style="bold green")
    return final_data

# --- Decryption Functions ---
def decrypt_data_ultimate(encrypted_data, passwords, rsa_key_password=None, ecc_key_password=None):
    try:
        if not encrypted_data or len(encrypted_data) < 16:
            raise ValueError("Invalid encrypted data!")
        salt_end = encrypted_data.find(b"|||")
        if salt_end == -1:
            raise ValueError("Invalid format: Separator '|||' not found.")
        salt = encrypted_data[:salt_end]
        metadata_end = encrypted_data.find(b"|||", salt_end + 3)
        if metadata_end == -1:
            raise ValueError("Invalid metadata format.")
        metadata_bytes = encrypted_data[salt_end + 3:metadata_end]
        ciphertext = encrypted_data[metadata_end + 3:]
        metadata = json.loads(metadata_bytes.decode('utf-8'))
        
        if len(passwords) < 3:
            raise ValueError("At least 3 passwords are required!")
        key, _ = generate_multi_key(passwords, base64.b64decode(metadata["salt"]))

        for i, pwd in enumerate(passwords):
            pwd_hash = base64.b64encode(hashlib.sha512(pwd.encode()).digest()).decode('utf-8')
            if pwd_hash != metadata["password_hashes"][i]:
                raise ValueError(f"Password {i+1} does not match!")

        if "layers" in metadata:
            return layered_decrypt(encrypted_data, passwords, rsa_key_password, ecc_key_password)

        method = metadata["method"]
        h = hmac.HMAC(key, hashes.SHA512(), backend=default_backend())
        h.update(ciphertext)
        h.verify(base64.b64decode(metadata["hmac"]))
        console.print(f"[+] HMAC verified for {method}!", style="bold yellow")

        if method == "hybrid":
            return hybrid_decrypt(encrypted_data, passwords, rsa_key_password)

        decrypted_data = ciphertext
        if method == "aes":
            nonce = base64.b64decode(metadata["nonce"])
            aesgcm = AESGCM(key[:32])
            decrypted_data = aesgcm.decrypt(nonce, decrypted_data, None)
            console.print("[+] Decrypted with AES-256-GCM!", style="bold magenta")
        elif method == "chacha":
            nonce = base64.b64decode(metadata["nonce"])
            chacha = ChaCha20Poly1305(key[:32])
            decrypted_data = chacha.decrypt(nonce, decrypted_data, None)
            console.print("[+] Decrypted with ChaCha20-Poly1305!", style="bold magenta")
        elif method == "fernet":
            fernet = Fernet(base64.urlsafe_b64encode(key[:32]))
            decrypted_data = fernet.decrypt(decrypted_data)
            console.print("[+] Decrypted with Fernet!", style="bold magenta")
        elif method == "rsa":
            if not os.path.exists(metadata["rsa_private_key"]):
                raise ValueError(f"RSA private key not found at {metadata['rsa_private_key']}")
            with open(metadata["rsa_private_key"], "rb") as f:
                private_key = serialization.load_pem_private_key(f.read(), password=rsa_key_password.encode() if rsa_key_password else None, backend=default_backend())
            decrypted_data = private_key.decrypt(
                decrypted_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA512()),
                    algorithm=hashes.SHA512(),
                    label=None
                )
            )
            console.print("[+] Decrypted with RSA-4096!", style="bold magenta")
        elif method == "ecc":
            if not os.path.exists(metadata["ecc_private_key"]) or not os.path.exists(metadata["ecc_public_key"]):
                raise ValueError(f"ECC keys not found!")
            with open(metadata["ecc_private_key"], "rb") as f:
                private_key = serialization.load_pem_private_key(f.read(), password=ecc_key_password.encode() if ecc_key_password else None, backend=default_backend())
            with open(metadata["ecc_public_key"], "rb") as f:
                public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
            shared_key = private_key.exchange(ec.ECDH(), public_key)
            derived_key = hashlib.sha512(shared_key).digest()[:32]
            nonce = base64.b64decode(metadata["nonce"])
            tag = base64.b64decode(metadata["ecc_tag"])
            cipher = Cipher(algorithms.AES(derived_key), modes.GCM(nonce, tag=tag), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(decrypted_data) + decryptor.finalize()
            console.print("[+] Decrypted with ECC (SECP384R1) + AES-GCM!", style="bold magenta")
        elif method == "tripledes":
            iv = base64.b64decode(metadata["nonce"])
            cipher = Cipher(TripleDES(key[:24]), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(decrypted_data) + decryptor.finalize()
            decrypted_data = unpad_data(decrypted_data)
            console.print("[+] Decrypted with Triple DES!", style="bold magenta")
        elif method == "twofish":
            tf = Twofish(key[:16])
            decrypted_data_blocks = b""
            for i in range(0, len(decrypted_data), 16):
                decrypted_data_blocks += tf.decrypt(decrypted_data[i:i+16])
            decrypted_data = unpad_data(decrypted_data_blocks)
            console.print("[+] Decrypted with Twofish!", style="bold magenta")

        console.print("[+] Decryption completed successfully!", style="bold green")
        return decrypted_data.decode()
    except Exception as e:
        console.print(f"[-] Decryption failed: {e}", style="bold red")
        return None

def hybrid_decrypt(encrypted_data, passwords, rsa_key_password=None):
    salt_end = encrypted_data.find(b"|||")
    salt = encrypted_data[:salt_end]
    metadata_end = encrypted_data.find(b"|||", salt_end + 3)
    metadata_bytes = encrypted_data[salt_end + 3:metadata_end]
    ciphertext = encrypted_data[metadata_end + 3:]
    metadata = json.loads(metadata_bytes.decode('utf-8'))
    key, _ = generate_multi_key(passwords, base64.b64decode(metadata["salt"]))

    for i, pwd in enumerate(passwords):
        pwd_hash = base64.b64encode(hashlib.sha512(pwd.encode()).digest()).decode('utf-8')
        if pwd_hash != metadata["password_hashes"][i]:
            raise ValueError(f"Password {i+1} does not match!")

    h = hmac.HMAC(key, hashes.SHA512(), backend=default_backend())
    h.update(ciphertext)
    h.verify(base64.b64decode(metadata["hmac"]))

    if not os.path.exists(metadata["private_key_file"]):
        raise ValueError(f"Hybrid private key not found at {metadata['private_key_file']}")
    with open(metadata["private_key_file"], "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=rsa_key_password.encode() if rsa_key_password else None, backend=default_backend())
    
    encrypted_aes_key = base64.b64decode(metadata["encrypted_key"])
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA512()),
            algorithm=hashes.SHA512(),
            label=None
        )
    )
    
    nonce = base64.b64decode(metadata["nonce"])
    aesgcm = AESGCM(aes_key)
    decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
    console.print("[+] Decrypted with Hybrid AES-256-GCM + RSA-4096!", style="bold magenta")
    return decrypted_data.decode()

def layered_decrypt(encrypted_data, passwords, rsa_key_password=None, ecc_key_password=None):
    salt_end = encrypted_data.find(b"|||")
    salt = encrypted_data[:salt_end]
    metadata_end = encrypted_data.find(b"|||", salt_end + 3)
    metadata_bytes = encrypted_data[salt_end + 3:metadata_end]
    ciphertext = encrypted_data[metadata_end + 3:]
    metadata = json.loads(metadata_bytes.decode('utf-8'))
    key, _ = generate_multi_key(passwords, base64.b64decode(metadata["salt"]))

    for i, pwd in enumerate(passwords):
        pwd_hash = base64.b64encode(hashlib.sha512(pwd.encode()).digest()).decode('utf-8')
        if pwd_hash != metadata["password_hashes"][i]:
            raise ValueError(f"Password {i+1} does not match!")

    decrypted_data = ciphertext
    layers = reversed(metadata["layers"])
    hmacs = reversed(metadata["hmacs"])

    layer_count = len(metadata["layers"])
    for idx, (layer, expected_hmac) in enumerate(zip(layers, hmacs), 1):
        h = hmac.HMAC(key, hashes.SHA512(), backend=default_backend())
        h.update(decrypted_data)
        h.verify(base64.b64decode(expected_hmac))
        console.print(f"[+] HMAC verified for {layer}!", style="bold yellow")

        if layer == "rsa":
            if not os.path.exists(metadata["rsa_private_key"]):
                raise ValueError(f"RSA private key not found at {metadata['rsa_private_key']}")
            with open(metadata["rsa_private_key"], "rb") as f:
                private_key = serialization.load_pem_private_key(f.read(), password=rsa_key_password.encode() if rsa_key_password else None, backend=default_backend())
            decrypted_data = private_key.decrypt(
                decrypted_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA512()),
                    algorithm=hashes.SHA512(),
                    label=None
                )
            )
            console.print(f"[+] Layer {layer_count}: Decrypted with RSA-4096!", style="bold magenta")
        elif layer == "ecc":
            if not os.path.exists(metadata["ecc_private_key"]) or not os.path.exists(metadata["ecc_public_key"]):
                raise ValueError(f"ECC keys not found!")
            with open(metadata["ecc_private_key"], "rb") as f:
                private_key = serialization.load_pem_private_key(f.read(), password=ecc_key_password.encode() if ecc_key_password else None, backend=default_backend())
            with open(metadata["ecc_public_key"], "rb") as f:
                public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
            shared_key = private_key.exchange(ec.ECDH(), public_key)
            derived_key = hashlib.sha512(shared_key).digest()[:32]
            nonce = base64.b64decode(metadata["nonces"]["ecc"])
            tag = base64.b64decode(metadata["ecc_tag"])
            cipher = Cipher(algorithms.AES(derived_key), modes.GCM(nonce, tag=tag), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(decrypted_data) + decryptor.finalize()
            console.print(f"[+] Layer {layer_count-1}: Decrypted with ECC (SECP384R1) + AES-GCM!", style="bold magenta")
        elif layer == "twofish":
            twofish_key = hashlib.sha512(key + b"TWOFISH").digest()[:16]
            tf = Twofish(twofish_key)
            decrypted_blocks = b""
            for i in range(0, len(decrypted_data), 16):
                decrypted_blocks += tf.decrypt(decrypted_data[i:i+16])
            decrypted_data = unpad_data(decrypted_blocks)
            console.print("[+] Layer 3: Decrypted with Twofish!", style="bold magenta")
        elif layer == "chacha":
            chacha_key = hashlib.sha512(key + b"CHACHA").digest()[:32]
            nonce = base64.b64decode(metadata["nonces"]["chacha"])
            chacha = ChaCha20Poly1305(chacha_key)
            decrypted_data = chacha.decrypt(nonce, decrypted_data, None)
            console.print("[+] Layer 2: Decrypted with ChaCha20-Poly1305!", style="bold magenta")
        elif layer == "aes":
            aes_key = hashlib.sha512(key + b"AES").digest()[:32]
            nonce = base64.b64decode(metadata["nonces"]["aes"])
            aesgcm = AESGCM(aes_key)
            decrypted_data = aesgcm.decrypt(nonce, decrypted_data, None)
            console.print("[+] Layer 1: Decrypted with AES-256-GCM!", style="bold magenta")

    console.print("[+] Decryption completed successfully!", style="bold green")
    return decrypted_data.decode()

# --- Save Encrypted Data ---
def save_encrypted_file(encrypted_data, output_file=None):
    if encrypted_data:
        output_file = output_file or os.path.join(os.getenv("HOME"), "encrypted.bin")
        with open(output_file, "wb") as f:
            f.write(encrypted_data)
        console.print(f"[+] Encrypted file saved as {output_file}", style="bold green")
    else:
        console.print("[-] No data to save!", style="bold red")

# --- Check Stored Passwords ---
def check_passwords(encrypted_file):
    try:
        with open(encrypted_file, "rb") as f:
            encrypted_data = f.read()
        salt_end = encrypted_data.find(b"|||")
        metadata_bytes = encrypted_data[salt_end + 3:encrypted_data.find(b"|||", salt_end + 3)]
        metadata = json.loads(metadata_bytes.decode('utf-8'))
        
        console.print("[+] Stored Password Hashes:", style="bold yellow")
        for i, pwd_hash in enumerate(metadata["password_hashes"], 1):
            console.print(f"Password {i} Hash: {pwd_hash[:20]}... (SHA512)", style="bold cyan")

        verify = Confirm.ask("[bold green]Do you want to manually verify or attempt passwords?[/bold green]", default=True)
        if verify:
            passwords = []
            for i in range(3):
                pwd = Prompt.ask(f"[bold magenta]Enter password {i+1} to verify/attempt[/bold magenta]", password=True)
                if not pwd.strip():
                    raise ValueError("Password cannot be empty!")
                passwords.append(pwd)
            
            try:
                rsa_key_password = Prompt.ask("[bold magenta]Enter RSA private key password (or Enter to skip)[/bold magenta]", password=True, default="")
                ecc_key_password = Prompt.ask("[bold magenta]Enter ECC private key password (or Enter to skip)[/bold magenta]", password=True, default="")
                decrypted = decrypt_data_ultimate(encrypted_data, passwords, rsa_key_password if rsa_key_password else None, ecc_key_password if ecc_key_password else None)
                if decrypted:
                    console.print(f"[+] Decryption successful! Decrypted data: {decrypted}", style="bold green")
                    return
            except Exception as e:
                console.print(f"[-] Password attempt failed: {e}", style="bold red")

            for i, pwd in enumerate(passwords):
                entered_hash = base64.b64encode(hashlib.sha512(pwd.encode()).digest()).decode('utf-8')
                stored_hash = metadata["password_hashes"][i]
                if entered_hash == stored_hash:
                    console.print(f"[+] Password {i+1} matches the hash!", style="bold green")
                else:
                    console.print(f"[-] Password {i+1} does not match the hash!", style="bold red")
    except Exception as e:
        console.print(f"[-] Failed to check passwords: {e}", style="bold red")

# --- Advanced Multi-Key Decryption ---
def decrypt_with_multiple_keys(encrypted_file):
    try:
        if not os.path.exists(encrypted_file):
            raise ValueError(f"Encrypted file not found at: {encrypted_file}")
        with open(encrypted_file, "rb") as f:
            encrypted_data = f.read()
        
        salt_end = encrypted_data.find(b"|||")
        metadata_bytes = encrypted_data[salt_end + 3:encrypted_data.find(b"|||", salt_end + 3)]
        metadata = json.loads(metadata_bytes.decode('utf-8'))

        rsa_key = Prompt.ask("[bold magenta]Enter RSA private key path or skip[/bold magenta]", default=metadata.get("rsa_private_key", os.path.join(os.getenv("HOME"), "layered_rsa_private_key.pem")))
        rsa_key_password = Prompt.ask("[bold magenta]Enter RSA private key password (or Enter to skip)[/bold magenta]", password=True, default="")
        rsa_pub_key = Prompt.ask("[bold magenta]Enter RSA public key path or skip[/bold magenta]", default=metadata.get("rsa_public_key", os.path.join(os.getenv("HOME"), "layered_rsa_public_key.pem")))
        ecc_priv_key = None
        ecc_key_password = None
        ecc_pub_key = None
        if "ecc_private_key" in metadata:
            ecc_priv_key = Prompt.ask("[bold magenta]Enter ECC private key path or skip[/bold magenta]", default=metadata.get("ecc_private_key", os.path.join(os.getenv("HOME"), "layered_ecc_keys_private.pem")))
            ecc_key_password = Prompt.ask("[bold magenta]Enter ECC private key password (or Enter to skip)[/bold magenta]", password=True, default="")
            ecc_pub_key = Prompt.ask("[bold magenta]Enter ECC public key path or skip[/bold magenta]", default=metadata.get("ecc_public_key", os.path.join(os.getenv("HOME"), "layered_ecc_keys_public.pem")))

        if rsa_key and not os.path.exists(rsa_key):
            raise ValueError(f"RSA private key not found at {rsa_key}")
        if rsa_pub_key and not os.path.exists(rsa_pub_key):
            raise ValueError(f"RSA public key not found at {rsa_pub_key}")
        if ecc_priv_key and not os.path.exists(ecc_priv_key):
            raise ValueError(f"ECC private key not found at {ecc_priv_key}")
        if ecc_pub_key and not os.path.exists(ecc_pub_key):
            raise ValueError(f"ECC public key not found at {ecc_pub_key}")

        if rsa_key:
            metadata["rsa_private_key"] = rsa_key
        if rsa_pub_key:
            metadata["rsa_public_key"] = rsa_pub_key
        if ecc_priv_key and ecc_pub_key:
            metadata["ecc_private_key"] = ecc_priv_key
            metadata["ecc_public_key"] = ecc_pub_key

        passwords = []
        for i in range(3):
            pwd = Prompt.ask(f"[bold magenta]Enter password {i+1}[/bold magenta]", password=True)
            if not pwd.strip():
                raise ValueError("Password cannot be empty!")
            passwords.append(pwd)

        decrypted = decrypt_data_ultimate(
            encrypted_data,
            passwords,
            rsa_key_password if rsa_key_password else None,
            ecc_key_password if ecc_key_password else None
        )
        if decrypted:
            console.print(f"[+] Decrypted data: {decrypted}", style="bold green")
        else:
            console.print("[!] Decryption failed!", style="bold yellow")
    except Exception as e:
        console.print(f"[-] Advanced decryption failed: {e}", style="bold red")

# --- Brute-Force Decryption (CPU only for Termux) ---
def brute_force_decrypt(encrypted_data, wordlist, max_workers=None):
    console.print("[+] Starting CPU-based brute-force (Hashcat may not work optimally on Termux)...", style="bold blue")
    try:
        if not os.path.exists(wordlist):
            raise ValueError(f"Wordlist not found at: {wordlist}")
        with open(wordlist, "r") as f:
            passwords = [p.strip() for p in f.read().splitlines() if p.strip()]
        if not passwords:
            raise ValueError("Wordlist is empty!")
    except Exception as e:
        console.print(f"[-] Error reading wordlist: {e}", style="bold red")
        return None

    max_workers = max_workers or min(multiprocessing.cpu_count() * 4, len(passwords))  # Adjusted for Termux
    def try_password(pwd):
        try:
            pwd_combo = [pwd, pwd, pwd]  # Assuming 3 identical passwords for simplicity
            decrypted = decrypt_data_ultimate(encrypted_data, pwd_combo)
            if decrypted:
                console.print(f"[+] Password found: {pwd}", style="bold green")
                return decrypted
        except:
            return None

    with Progress() as progress:
        task = progress.add_task("[cyan]Brute-forcing...", total=len(passwords))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(try_password, pwd): pwd for pwd in passwords}
            for future in as_completed(futures):
                progress.advance(task)
                result = future.result()
                if result:
                    return result
    console.print("[-] Brute-force failed!", style="bold red")
    return None

# --- Decryption Fast Tool (Simplified for Termux) ---
def run_fast_decryption(hash_file, wordlist=None):
    console.print("[+] Running CPU-based decryption (GPU support limited on Termux)...", style="bold blue")
    if not os.path.exists(hash_file):
        console.print(f"[-] File not found: {hash_file}", style="bold red")
        return
    with open(hash_file, "rb") as f:
        encrypted_data = f.read()
    if wordlist and os.path.exists(wordlist):
        decrypted = brute_force_decrypt(encrypted_data, wordlist)
        if decrypted:
            console.print(f"[+] Decrypted data: {decrypted}", style="bold green")
        else:
            console.print("[-] Decryption failed!", style="bold red")
    else:
        console.print("[-] Wordlist required for brute-force!", style="bold red")

# --- Password Generate Tool ---
def generate_all_passwords(length, chars=string.ascii_letters + string.digits + string.punctuation):
    from itertools import product
    passwords = [''.join(p) for p in product(chars, repeat=length)]
    return passwords

def generate_secure_password(length, use_numbers=True, use_letters=True, use_special=True, custom_chars=None):
    chars = custom_chars or ""
    if not chars:
        if use_numbers: chars += string.digits
        if use_letters: chars += string.ascii_letters
        if use_special: chars += string.punctuation
    if not chars:
        raise ValueError("No character set selected!")
    return ''.join(secrets.choice(chars) for _ in range(length))

def save_password_list(passwords, output_file):
    with open(output_file, "w") as f:
        f.write("\n".join(passwords))
    console.print(f"[+] Saved to {output_file}", style="bold green")

# --- Main Menu ---
def main():
    banner()
    try:
        while True:
            console.print("\n[bold cyan]Choose a category:[/bold cyan]")
            console.print("1. Encryption Tool")
            console.print("2. Decryption Tool")
            console.print("3. Advanced Multi-Key Decryption")
            console.print("4. Password Generate Tool")
            console.print("5. Decryption Fast Tool (CPU Only)")
            console.print("6. Check Stored Passwords")
            console.print("7. Exit")
            choice = Prompt.ask("[bold green]Enter your choice (1-7)[/bold green]")

            if choice == "1":
                data = Prompt.ask("[bold green]Enter data to encrypt[/bold green]")
                passwords = []
                for i in range(3):
                    pwd = Prompt.ask(f"[bold magenta]Enter password {i+1}[/bold magenta]", password=True)
                    if not pwd.strip():
                        raise ValueError("Password cannot be empty!")
                    passwords.append(pwd)
                console.print("\n[bold cyan]Encryption Methods:[/bold cyan]")
                console.print("1. AES-256-GCM\n2. ChaCha20-Poly1305\n3. Fernet\n4. RSA-4096\n5. ECC+AES\n6. TripleDES\n7. Twofish\n8. Hybrid (AES+RSA)\n9. Layered (v9.0)")
                method_choice = Prompt.ask("[bold green]Choose method (1-9)[/bold green]")
                methods = {"1": "aes", "2": "chacha", "3": "fernet", "4": "rsa", "5": "ecc", "6": "tripledes", "7": "twofish", "8": "hybrid", "9": "layered"}
                method = methods.get(method_choice, "aes")
                encrypted = encrypt_data_ultimate(data, passwords, method)
                if encrypted:
                    output_file = Prompt.ask("[bold green]Output file name[/bold green]", default=os.path.join(os.getenv("HOME"), "encrypted.bin"))
                    save_encrypted_file(encrypted, output_file)

            elif choice == "2":
                file_path = Prompt.ask("[bold green]Enter encrypted file path[/bold green]").strip("'\"")
                if not os.path.exists(file_path):
                    console.print(f"[-] File not found!", style="bold red")
                    continue
                passwords = []
                for i in range(3):
                    pwd = Prompt.ask(f"[bold magenta]Enter password {i+1}[/bold magenta]", password=True)
                    if not pwd.strip():
                        raise ValueError("Password cannot be empty!")
                    passwords.append(pwd)
                rsa_key_password = Prompt.ask("[bold magenta]Enter RSA private key password (or Enter to skip)[/bold magenta]", password=True, default="")
                ecc_key_password = Prompt.ask("[bold magenta]Enter ECC private key password (or Enter to skip)[/bold magenta]", password=True, default="")
                with open(file_path, "rb") as f:
                    encrypted_data = f.read()
                decrypted = decrypt_data_ultimate(encrypted_data, passwords, rsa_key_password if rsa_key_password else None, ecc_key_password if ecc_key_password else None)
                if decrypted:
                    console.print(f"[+] Decrypted: {decrypted}", style="bold green")

            elif choice == "3":
                file_path = Prompt.ask("[bold green]Enter encrypted file path[/bold green]").strip("'\"")
                if not os.path.exists(file_path):
                    console.print(f"[-] File not found!", style="bold red")
                    continue
                decrypt_with_multiple_keys(file_path)

            elif choice == "4":
                mode = Prompt.ask("[bold green]1. Generate random passwords\n2. Generate all possible passwords[/bold green]", default="1")
                if mode == "1":
                    length = int(Prompt.ask("[bold green]Enter length[/bold green]", default="16"))
                    use_numbers = Confirm.ask("[bold green]Numbers?[/bold green]", default=True)
                    use_letters = Confirm.ask("[bold green]Letters?[/bold green]", default=True)
                    use_special = Confirm.ask("[bold green]Special chars?[/bold green]", default=True)
                    custom = Prompt.ask("[bold green]Custom chars (leave blank for default)[/bold green]", default="")
                    count = int(Prompt.ask("[bold green]How many?[/bold green]", default="10"))
                    passwords = [generate_secure_password(length, use_numbers, use_letters, use_special, custom) for _ in range(count)]
                else:
                    length = int(Prompt.ask("[bold green]Enter length (max 6 for Termux performance)[/bold green]", default="4"))
                    if length > 6:
                        console.print("[-] Max length is 6 on Termux!", style="bold red")
                        length = 6
                    custom = Prompt.ask("[bold green]Custom chars (leave blank for all)[/bold green]", default="")
                    passwords = generate_all_passwords(length, custom or None)
                console.print("[+] Generated Passwords:", style="bold green")
                for pwd in passwords[:10]:
                    console.print(pwd)
                if Confirm.ask("[bold green]Save to file?[/bold green]"):
                    output_file = Prompt.ask("[bold green]Output file[/bold green]", default=os.path.join(os.getenv("HOME"), "passwords.txt"))
                    save_password_list(passwords, output_file)

            elif choice == "5":
                hash_file = Prompt.ask("[bold green]Enter encrypted file path[/bold green]").strip("'\"")
                if not os.path.exists(hash_file):
                    console.print(f"[-] File not found!", style="bold red")
                    continue
                wordlist = Prompt.ask("[bold green]Wordlist path[/bold green]").strip("'\"")
                if not os.path.exists(wordlist):
                    console.print(f"[-] Wordlist not found!", style="bold red")
                    continue
                run_fast_decryption(hash_file, wordlist)

            elif choice == "6":
                file_path = Prompt.ask("[bold green]Enter encrypted file path[/bold green]").strip("'\"")
                if not os.path.exists(file_path):
                    console.print(f"[-] File not found!", style="bold red")
                    continue
                check_passwords(file_path)

            elif choice == "7":
                console.print("[bold green]Exiting...[/bold green]")
                break
            else:
                console.print("[-] Invalid choice!", style="bold red")
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Interrupted by user. Exiting gracefully...[/bold yellow]")
    except Exception as e:
        console.print(f"[-] Unexpected error: {e}", style="bold red")

if __name__ == "__main__":
    main()