import os
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature

def load_private_key(private_key_str):
    """Charge une clé privée à partir d'une chaîne PEM."""
    return serialization.load_pem_private_key(
        private_key_str.encode('utf-8'),
        password=None,
        backend=default_backend()
    )

def load_public_key(public_key_str):
    """Charge une clé publique à partir d'une chaîne PEM."""
    return serialization.load_pem_public_key(
        public_key_str.encode('utf-8'),
        backend=default_backend()
    )

def generate_keys():
    """Génère une paire de clés RSA (privée et publique)."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem, public_pem

def generate_symmetric_key():
    """Génère une clé symétrique de 256 bits (32 octets)."""
    return os.urandom(32)

def encrypt_symmetric_key(public_key, symmetric_key):
    """Chiffre une clé symétrique à l'aide d'une clé publique."""
    encrypted_key = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key

def decrypt_symmetric_key(private_key, encrypted_key):
    """Déchiffre une clé symétrique à l'aide d'une clé privée."""
    return private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def encrypt_private_key(key, private_key):
    """Chiffre une clé privée à l'aide d'une clé symétrique."""
    if not isinstance(key, bytes):
        raise ValueError("Key must be bytes-like")
    
    iv = os.urandom(16)  # Génération d'un vecteur d'initialisation
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_private_key = encryptor.update(private_key) + encryptor.finalize()
    return iv + encrypted_private_key

def decrypt_private_key(encrypted_private_key, password, salt):
    """Déchiffre une clé privée chiffrée."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    
    iv = encrypted_private_key[:16]  # Extraction du vecteur d'initialisation
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    private_key = decryptor.update(encrypted_private_key[16:]) + decryptor.finalize()
    return private_key

def load_and_decrypt_private_key(encrypted_private_key, password, salt):
    """Charge et déchiffre une clé privée à partir d'une clé chiffrée."""
    encrypted_private_key = base64.b64decode(encrypted_private_key)
    salt = base64.b64decode(salt)
    decrypted_private_key = decrypt_private_key(encrypted_private_key, password, salt)
    private_key = serialization.load_pem_private_key(
        decrypted_private_key,
        password=None,
        backend=default_backend()
    )
    return private_key

def generate_encryption_key(password: str):
    """Génère une clé d'encryption à partir d'un mot de passe."""
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key, salt

def encrypt_message(public_key, plaintext):
    """Chiffre un message à l'aide d'une clé publique et d'une clé symétrique."""
    symmetric_key = generate_symmetric_key()
    iv = os.urandom(16)  # Vecteur d'initialisation pour AES
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    encrypted_key = encrypt_symmetric_key(public_key, symmetric_key)
    return encrypted_key + iv + ciphertext

def decrypt_message(private_key, encrypted_message):
    """Déchiffre un message à l'aide d'une clé privée."""
    encrypted_key_length = 256  # Longueur de la clé RSA (2048 bits)
    encrypted_key = encrypted_message[:encrypted_key_length]
    iv = encrypted_message[encrypted_key_length:encrypted_key_length + 16]
    ciphertext = encrypted_message[encrypted_key_length + 16:]

    symmetric_key = decrypt_symmetric_key(private_key, encrypted_key)
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext

def sign_message(private_key, message):
    """Signe un message avec une clé privée."""
    if isinstance(message, str):
        message = message.encode('utf-8')

    # Signature du message
    signature = private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    # Encode la signature en Base64
    b64_signature = base64.b64encode(signature).decode('utf-8')
    
    return b64_signature

def verify_signature(public_key, message, signature):
    """Vérifie la validité d'une signature avec une clé publique."""
    try:
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        public_key.verify(
            signature,
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

def hash_message(content):
    """Calcule le hachage SHA-256 d'un contenu."""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(content)
    return digest.finalize()