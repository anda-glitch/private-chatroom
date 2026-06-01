import os
import hashlib
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend

# --- Diffie-Hellman Key Exchange ---
# RFC 3526 Group 14, 2048-bit MODP Group
P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
)
DH_P = int(P_HEX, 16)
DH_G = 2

def generate_dh_private():
    """Generates a random private key for DH."""
    return secrets.randbits(2048)

def generate_dh_public(private_key):
    """Generates the public key from the private key."""
    return pow(DH_G, private_key, DH_P)

def compute_dh_shared_secret(private_key, other_public_key):
    """Computes the shared secret from our private key and their public key."""
    secret = pow(other_public_key, private_key, DH_P)
    # Hash to get a 32-byte key for AES-256
    return hashlib.sha256(str(secret).encode()).digest()


# --- Authenticated Encryption Wrapper (Using Cryptography Lib) ---

def encrypt_message(plaintext_bytes, shared_secret_key):
    """
    Encrypts and authenticates a message using AES-256-CTR and HMAC-SHA256.
    Returns: IV (16) + HMAC (32) + Ciphertext (N)
    """
    iv = os.urandom(16)
    
    # Encrypt using AES-256-CTR
    cipher = Cipher(algorithms.AES(shared_secret_key), modes.CTR(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext_bytes) + encryptor.finalize()
    
    # Calculate HMAC over IV + Ciphertext
    h = hmac.HMAC(shared_secret_key, hashes.SHA256(), backend=default_backend())
    h.update(iv + ciphertext)
    mac = h.finalize()
    
    return iv + mac + ciphertext

def decrypt_message(payload_bytes, shared_secret_key):
    """
    Verifies and decrypts a message using AES-256-CTR and HMAC-SHA256.
    Payload: IV (16) + HMAC (32) + Ciphertext (N)
    Returns: Plaintext bytes, or None if authentication fails.
    """
    if len(payload_bytes) < 48:
        return None # Too short
        
    iv = payload_bytes[:16]
    mac_received = payload_bytes[16:48]
    ciphertext = payload_bytes[48:]
    
    # Verify HMAC
    h = hmac.HMAC(shared_secret_key, hashes.SHA256(), backend=default_backend())
    h.update(iv + ciphertext)
    
    try:
        h.verify(mac_received)
    except Exception:
        return None # Tampered or corrupted
        
    # Decrypt
    cipher = Cipher(algorithms.AES(shared_secret_key), modes.CTR(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    return plaintext

if __name__ == "__main__":
    # Simple test to verify crypto functions work
    print("Testing Diffie-Hellman...")
    privA = generate_dh_private()
    pubA = generate_dh_public(privA)
    privB = generate_dh_private()
    pubB = generate_dh_public(privB)
    
    secA = compute_dh_shared_secret(privA, pubB)
    secB = compute_dh_shared_secret(privB, pubA)
    assert secA == secB
    print("DH Secret Match:", secA.hex())
    
    print("Testing AES-CTR + HMAC (cryptography library)...")
    msg = b"Hello world! This is a secure message using standard cryptography."
    enc = encrypt_message(msg, secA)
    dec = decrypt_message(enc, secB)
    assert msg == dec
    print("Encryption/Decryption successful!")
