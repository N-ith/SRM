"""Cryptographic operations for secure deletion."""

import secrets
import hashlib
from enum import Enum

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class PatternType(Enum):
    """Types of overwrite patterns."""
    RANDOM = "random"
    ZEROS = "zeros"
    ONES = "ones"
    ALTERNATING = "alternating"


class CryptoEngine:
    """Handles all cryptographic operations."""
    
    @staticmethod
    def generate_key() -> bytes:
        """Generate 256-bit ephemeral encryption key."""
        return secrets.token_bytes(32)
    
    @staticmethod
    def encrypt_data(data: bytes, use_chacha20: bool = False) -> bytes:
        """Encrypt data with ephemeral key (key destroyed after use)."""
        key = CryptoEngine.generate_key()
        
        if use_chacha20:
            nonce = secrets.token_bytes(16)
            cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, 
                          backend=default_backend())
        else:
            iv = secrets.token_bytes(16)
            cipher = Cipher(algorithms.AES(key), modes.CTR(iv), 
                          backend=default_backend())
        
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(data) + encryptor.finalize()
        del key  # Destroy key
        
        return encrypted
    
    @staticmethod
    def generate_pattern(size: int, pattern_type: PatternType) -> bytes:
        """Generate overwrite pattern of specified size."""
        if pattern_type == PatternType.RANDOM:
            return secrets.token_bytes(size)
        elif pattern_type == PatternType.ZEROS:
            return b'\x00' * size
        elif pattern_type == PatternType.ONES:
            return b'\xff' * size
        else:  # ALTERNATING
            return bytes([0xAA if i % 2 == 0 else 0x55 for i in range(size)])
    
    @staticmethod
    def hash_path(file_path: str) -> str:
        """Generate SHA-256 hash of file path for logging."""
        return hashlib.sha256(file_path.encode()).hexdigest()
