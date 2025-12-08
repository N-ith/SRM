"""Metadata sanitization for secure deletion."""

import os
import time
import secrets
from pathlib import Path
from typing import Optional


class MetadataSanitizer:
    """Handles metadata sanitization operations."""
    
    @staticmethod
    def randomize_timestamps(file_path: Path) -> bool:
        """Randomize file access and modification timestamps.
        
        Args:
            file_path: Path to file/directory
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Random time within last year
            random_time = time.time() - secrets.randbelow(31536000)
            os.utime(file_path, (random_time, random_time))
            return True
        except Exception:
            return False
    
    @staticmethod
    def generate_random_name(length: int = 16) -> str:
        """Generate random filename for obfuscation.
        
        Args:
            length: Length of random name
            
        Returns:
            Random alphanumeric string
        """
        chars = "abcdefghijklmnopqrstuvwxyz0123456789"
        return ''.join(secrets.choice(chars) for _ in range(length))
    
    @staticmethod
    def rename_file(file_path: Path, iterations: int = 3) -> Optional[Path]:
        """Rename file multiple times with random names.
        
        Args:
            file_path: Path to file/directory
            iterations: Number of rename operations
            
        Returns:
            Final path after renaming, or original path if failed
        """
        current_path = file_path
        
        try:
            for _ in range(iterations):
                new_name = MetadataSanitizer.generate_random_name()
                new_path = current_path.parent / new_name
                current_path.rename(new_path)
                current_path = new_path
            
            return current_path
        except Exception:
            return current_path