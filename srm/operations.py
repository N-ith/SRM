"""File and directory operations for secure deletion."""

import os
import time
import secrets
from pathlib import Path
from typing import Optional

from srm.crypto import CryptoEngine, PatternType


class FileOps:
    """File-level operations."""
    
    def __init__(self, passes: int, use_chacha20: bool, sanitize: bool):
        self.passes = passes
        self.use_chacha20 = use_chacha20
        self.sanitize = sanitize
        self.crypto = CryptoEngine()
    
    def encrypt(self, path: Path) -> bool:
        """Encrypt file contents with ephemeral key."""
        try:
            with open(path, 'rb') as f:
                data = f.read()
            
            encrypted = self.crypto.encrypt_data(data, self.use_chacha20)
            
            with open(path, 'wb') as f:
                f.write(encrypted)
                f.flush()
                os.fsync(f.fileno())
            return True
        except Exception:
            return False
    
    def overwrite(self, path: Path) -> bool:
        """Perform multiple overwrite passes."""
        try:
            size = path.stat().st_size
            patterns = [PatternType.RANDOM, PatternType.ZEROS, PatternType.ONES, 
                       PatternType.ALTERNATING, PatternType.RANDOM]
            
            with open(path, 'rb+') as f:
                for i in range(self.passes):
                    pattern_type = patterns[i % len(patterns)]
                    f.seek(0)
                    
                    # Write in 1MB chunks
                    remaining = size
                    while remaining > 0:
                        chunk = min(1024 * 1024, remaining)
                        data = self.crypto.generate_pattern(chunk, pattern_type)
                        f.write(data)
                        remaining -= chunk
                    
                    f.flush()
                    os.fsync(f.fileno())
            return True
        except Exception:
            return False
    
    def sanitize_metadata(self, path: Path) -> Path:
        """Randomize timestamps and rename file."""
        if not self.sanitize:
            return path
        
        # Randomize timestamp
        try:
            random_time = time.time() - secrets.randbelow(31536000)
            os.utime(path, (random_time, random_time))
        except (OSError, PermissionError) as e:
            # File may be locked or permission denied - continue anyway
            pass  # nosec B110
        
        # Rename 3 times
        for _ in range(3):
            try:
                chars = "abcdefghijklmnopqrstuvwxyz0123456789"
                new_name = ''.join(secrets.choice(chars) for _ in range(16))
                new_path = path.parent / new_name
                path.rename(new_path)
                path = new_path
            except (OSError, FileExistsError) as e:
                # Rename collision or permission issue - try next iteration
                continue
        
        return path
    
    def unlink(self, path: Path) -> bool:
        """Delete file from filesystem."""
        try:
            path.unlink()
            return True
        except Exception:
            return False


class DirOps:
    """Directory-level operations."""
    
    def __init__(self, sanitize: bool):
        self.sanitize = sanitize
    
    def collect_contents(self, path: Path) -> tuple[list[Path], list[Path]]:
        """Get all files and subdirectories (depth-first)."""
        files, dirs = [], []
        
        for root, subdirs, filenames in os.walk(path, topdown=False):
            for f in filenames:
                files.append(Path(root) / f)
            for d in subdirs:
                dirs.append(Path(root) / d)
        
        return files, dirs
    
    def remove_dir(self, path: Path) -> bool:
        """Sanitize and remove directory."""
        try:
            if self.sanitize:
                # Randomize timestamp
                random_time = time.time() - secrets.randbelow(31536000)
                os.utime(path, (random_time, random_time))
                
                # Rename
                chars = "abcdefghijklmnopqrstuvwxyz0123456789"
                new_name = ''.join(secrets.choice(chars) for _ in range(16))
                new_path = path.parent / new_name
                path.rename(new_path)
                path = new_path
            
            path.rmdir()
            return True
        except Exception:
            return False