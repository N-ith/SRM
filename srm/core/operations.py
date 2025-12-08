"""Low-level file and directory operations."""

import os
from pathlib import Path
from typing import Optional

from srm.config import SecureDeletionConfig
from srm.crypto.engine import CryptoEngine
from srm.crypto.patterns import OverwritePattern
from srm.metadata.sanitizer import MetadataSanitizer


class FileOperations:
    """Low-level file operations for secure deletion."""
    
    def __init__(self, config: SecureDeletionConfig):
        self.config = config
        self.crypto = CryptoEngine()
        self.sanitizer = MetadataSanitizer()
    
    def encrypt_contents(self, file_path: Path) -> bool:
        """Encrypt file contents with ephemeral key.
        
        Args:
            file_path: Path to file
            
        Returns:
            True if successful
        """
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            encrypted = self.crypto.encrypt_data(data, self.config.use_chacha20)
            
            with open(file_path, 'wb') as f:
                f.write(encrypted)
                f.flush()
                os.fsync(f.fileno())
            
            return True
        except Exception:
            return False
    
    def overwrite_contents(self, file_path: Path) -> bool:
        """Perform multiple overwrite passes on file.
        
        Args:
            file_path: Path to file
            
        Returns:
            True if successful
        """
        try:
            file_size = file_path.stat().st_size
            patterns = OverwritePattern.get_default_sequence()
            
            with open(file_path, 'rb+') as f:
                for pass_num in range(self.config.overwrite_passes):
                    pattern_type = patterns[pass_num % len(patterns)]
                    
                    # Overwrite in 1MB chunks
                    chunk_size = 1024 * 1024
                    f.seek(0)
                    
                    remaining = file_size
                    while remaining > 0:
                        write_size = min(chunk_size, remaining)
                        pattern = OverwritePattern.generate(write_size, pattern_type)
                        f.write(pattern)
                        remaining -= write_size
                    
                    f.flush()
                    os.fsync(f.fileno())
            
            return True
        except Exception:
            return False
    
    def sanitize_metadata(self, file_path: Path) -> Path:
        """Sanitize file metadata (timestamps and name).
        
        Args:
            file_path: Path to file
            
        Returns:
            Final path after sanitization
        """
        self.sanitizer.randomize_timestamps(file_path)
        return self.sanitizer.rename_file(file_path)
    
    def unlink(self, file_path: Path) -> bool:
        """Unlink (delete) file from filesystem.
        
        Args:
            file_path: Path to file
            
        Returns:
            True if successful
        """
        try:
            file_path.unlink()
            return True
        except Exception:
            return False


class DirectoryOperations:
    """Operations for secure directory deletion."""
    
    def __init__(self, config: SecureDeletionConfig):
        self.config = config
        self.sanitizer = MetadataSanitizer()
    
    def collect_contents(self, dir_path: Path) -> tuple[list[Path], list[Path]]:
        """Collect all files and subdirectories.
        
        Args:
            dir_path: Path to directory
            
        Returns:
            Tuple of (files, directories)
        """
        all_files = []
        all_dirs = []
        
        for root, dirs, files in os.walk(dir_path, topdown=False):
            for file in files:
                file_path = Path(root) / file
                all_files.append(file_path)
            
            for d in dirs:
                dir_full_path = Path(root) / d
                all_dirs.append(dir_full_path)
        
        return all_files, all_dirs
    
    def sanitize_and_remove(self, dir_path: Path) -> bool:
        """Sanitize directory metadata and remove it.
        
        Args:
            dir_path: Path to directory
            
        Returns:
            True if successful
        """
        try:
            if self.config.sanitize_metadata:
                self.sanitizer.randomize_timestamps(dir_path)
                dir_path = self.sanitizer.rename_file(dir_path)
            
            dir_path.rmdir()
            return True
        except Exception:
            return False