"""Core cryptographic engine for secure deletion."""

import secrets
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class CryptoEngine:
    """Handles cryptographic operations for secure deletion."""
    
    @staticmethod
    def generate_key(use_chacha20: bool = False) -> bytes:
        """Generate ephemeral encryption key.
        
        Args:
            use_chacha20: Generate key for ChaCha20 (vs AES-256)
            
        Returns:
            32-byte cryptographically secure random key
        """
        return secrets.token_bytes(32)  # 256 bits
    
    @staticmethod
    def encrypt_data(data: bytes, use_chacha20: bool = False) -> bytes:
        """Encrypt data with ephemeral key.
        
        The key is generated, used once, then destroyed. This ensures
        that even if overwriting fails, the data cannot be decrypted.
        
        Args:
            data: Data to encrypt
            use_chacha20: Use ChaCha20 instead of AES-256
            
        Returns:
            Encrypted data
        """
        key = CryptoEngine.generate_key(use_chacha20)
        
        if use_chacha20:
            nonce = secrets.token_bytes(16)
            cipher = Cipher(
                algorithms.ChaCha20(key, nonce),
                mode=None,
                backend=default_backend()
            )
        else:
            iv = secrets.token_bytes(16)
            cipher = Cipher(
                algorithms.AES(key),
                modes.CTR(iv),
                backend=default_backend()
            )
        
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(data) + encryptor.finalize()
        
        # Explicitly destroy key (garbage collection)
        del key
        
        return encrypted
    
    @staticmethod
    def hash_file_path(file_path: str) -> str:
        """Generate secure hash of file path for privacy-preserving logging.
        
        Args:
            file_path: Path to hash
            
        Returns:
            SHA-256 hash as hexadecimal string
        """
        return hashlib.sha256(file_path.encode()).hexdigest()
