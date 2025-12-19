"""Main secure deletion orchestrator."""

from pathlib import Path
from datetime import datetime

from srm.operations import FileOps, DirOps
from srm.crypto import CryptoEngine


class SecureFileDeleter:
    """Orchestrates secure file and directory deletion."""
    
    def __init__(self, passes: int = 3, use_chacha20: bool = False,
                 sanitize: bool = True, log: bool = False, verbose: bool = False):
        self.file_ops = FileOps(passes, use_chacha20, sanitize)
        self.dir_ops = DirOps(sanitize)
        self.log_enabled = log
        self.verbose = verbose
        self.crypto = CryptoEngine()
        
        self.files_deleted = 0
        self.dirs_deleted = 0
        self.log_entries = []
    
    def _log(self, msg: str) -> None:
        """Print if verbose mode enabled."""
        if self.verbose:
            print(f"[srm] {msg}")
    
    def _add_log_entry(self, path: str, success: bool) -> None:
        """Add entry to secure log."""
        if self.log_enabled:
            self.log_entries.append({
                'timestamp': datetime.now().isoformat(),
                'path_hash': self.crypto.hash_path(path)[:16],
                'success': success
            })
    
    def delete_file(self, file_path: str) -> bool:
        """Securely delete a file."""
        path = Path(file_path)
        
        if not path.exists() or not path.is_file():
            print(f"Error: Not a valid file: {file_path}")
            return False
        
        original = str(path.absolute())
        
        try:
            self._log(f"Encrypting: {path.name}")
            if not self.file_ops.encrypt(path):
                return False
            
            self._log(f"Overwriting: {path.name}")
            if not self.file_ops.overwrite(path):
                return False
            
            self._log(f"Sanitizing: {path.name}")
            path = self.file_ops.sanitize_metadata(path)
            
            self._log(f"Unlinking: {path.name}")
            success = self.file_ops.unlink(path)
            
            if success:
                self.files_deleted += 1
                self._log(f"✓ Deleted: {original}")
            
            self._add_log_entry(original, success)
            return success
            
        except Exception as e:
            print(f"Error: {e}")
            self._add_log_entry(original, False)
            return False
    
    def delete_directory(self, dir_path: str) -> bool:
        """Recursively delete directory and all contents."""
        path = Path(dir_path)
        
        if not path.exists() or not path.is_dir():
            print(f"Error: Not a valid directory: {dir_path}")
            return False
        
        self._log(f"Processing directory: {dir_path}")
        
        try:
            # Get all files and subdirectories
            files, dirs = self.dir_ops.collect_contents(path)
            
            # Delete all files
            for f in files:
                self.delete_file(str(f))
            
            # Remove all subdirectories
            for d in dirs:
                if self.dir_ops.remove_dir(d):
                    self.dirs_deleted += 1
            
            # Remove root directory
            if self.dir_ops.remove_dir(path):
                self.dirs_deleted += 1
                return True
            
            return False
            
        except Exception as e:
            print(f"Error: {e}")
            return False
    
    def print_log(self) -> None:
        """Print deletion log."""
        if not self.log_entries:
            return
        
        print("\n=== Deletion Log ===")
        for entry in self.log_entries:
            status = "✓" if entry['success'] else "✗"
            print(f"{status} {entry['timestamp']} | Hash: {entry['path_hash']}...")
