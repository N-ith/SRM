"""Secure deletion logging functionality."""

from typing import List
from datetime import datetime

from srm.config import SecureDeletionConfig
from srm.crypto.engine import CryptoEngine


class DeletionLogger:
    """Handles secure logging of deletion operations."""
    
    def __init__(self, config: SecureDeletionConfig):
        self.config = config
        self.crypto = CryptoEngine()
        self.deletion_log: List[dict] = []
    
    def log_deletion(self, file_path: str, success: bool, config: SecureDeletionConfig) -> None:
        """Log a deletion operation.
        
        Args:
            file_path: Original file path
            success: Whether deletion succeeded
            config: Deletion configuration used
        """
        if not self.config.secure_log:
            return
        
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'path_hash': self.crypto.hash_file_path(file_path),
            'success': success,
            'algorithm': 'ChaCha20' if config.use_chacha20 else 'AES-256',
            'passes': config.overwrite_passes
        }
        self.deletion_log.append(log_entry)
    
    def print_log(self) -> None:
        """Print deletion log to console."""
        if not self.deletion_log:
            print("No deletion operations logged.")
            return
        
        print("\n=== Secure Deletion Log ===")
        for entry in self.deletion_log:
            print(f"\nTimestamp: {entry['timestamp']}")
            print(f"Path Hash: {entry['path_hash'][:16]}...")
            print(f"Algorithm: {entry['algorithm']}")
            print(f"Passes: {entry['passes']}")
            print(f"Success: {entry['success']}")
