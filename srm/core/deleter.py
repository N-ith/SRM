"""Main secure deletion orchestrator."""

import os
from pathlib import Path
from typing import List

from srm.config import SecureDeletionConfig
from srm.core.operations import FileOperations, DirectoryOperations
from srm.utils.logger import DeletionLogger


class SecureFileDeleter:
    """Orchestrates secure file and directory deletion."""
    
    def __init__(self, config: SecureDeletionConfig):
        self.config = config
        self.file_ops = FileOperations(config)
        self.dir_ops = DirectoryOperations(config)
        self.logger = DeletionLogger(config)
        
        self.files_processed = 0
        self.dirs_processed = 0
    
    def _log_message(self, message: str) -> None:
        """Print message if verbose mode enabled."""
        if self.config.verbose:
            print(f"[srm] {message}")
    
    def secure_delete(self, file_path: str) -> bool:
        """Perform secure deletion of a file.
        
        Process:
        1. One-time encryption with ephemeral key
        2. Multiple overwrite passes with cryptographic patterns
        3. Metadata sanitization (timestamps, renaming)
        4. Final unlinking
        5. Optional secure logging
        
        Args:
            file_path: Path to file
            
        Returns:
            True if deletion successful
        """
        path = Path(file_path)
        
        if not path.exists():
            print(f"Error: File not found: {file_path}")
            return False
        
        if not path.is_file():
            print(f"Error: Not a regular file: {file_path}")
            return False
        
        original_path = str(path.absolute())
        
        try:
            # Step 1: Encrypt
            self._log_message(f"Encrypting: {path}")
            if not self.file_ops.encrypt_contents(path):
                return False
            
            # Step 2: Overwrite
            self._log_message(f"Overwriting: {path}")
            if not self.file_ops.overwrite_contents(path):
                return False
            
            # Step 3: Sanitize metadata
            if self.config.sanitize_metadata:
                self._log_message(f"Sanitizing metadata: {path}")
                path = self.file_ops.sanitize_metadata(path)
            
            # Step 4: Unlink
            self._log_message(f"Unlinking: {path}")
            success = self.file_ops.unlink(path)
            
            # Step 5: Log
            self.logger.log_deletion(original_path, success, self.config)
            
            if success:
                self._log_message(f"Successfully deleted: {original_path}")
                self.files_processed += 1
            
            return success
            
        except Exception as e:
            print(f"Error during secure deletion: {e}")
            self.logger.log_deletion(original_path, False, self.config)
            return False
    
    def secure_delete_directory(self, dir_path: str) -> bool:
        """Recursively secure delete directory and contents.
        
        Process:
        1. Walk directory tree (depth-first)
        2. Delete all files securely
        3. Remove empty directories
        
        Args:
            dir_path: Path to directory
            
        Returns:
            True if all contents deleted successfully
        """
        path = Path(dir_path)
        
        if not path.exists():
            print(f"Error: Directory not found: {dir_path}")
            return False
        
        if not path.is_dir():
            print(f"Error: Not a directory: {dir_path}")
            return False
        
        self._log_message(f"Processing directory: {dir_path}")
        
        try:
            # Collect all files and directories
            all_files, all_dirs = self.dir_ops.collect_contents(path)
            
            # Delete all files
            file_success = 0
            for file_path in all_files:
                if self.secure_delete(str(file_path)):
                    file_success += 1
            
            # Remove directories (bottom-up)
            for dir_path in all_dirs:
                if self.dir_ops.sanitize_and_remove(dir_path):
                    self._log_message(f"Removed directory: {dir_path}")
                    self.dirs_processed += 1
            
            # Remove root directory
            if self.dir_ops.sanitize_and_remove(path):
                self._log_message(f"Removed root directory: {path}")
                self.dirs_processed += 1
            else:
                return False
            
            return file_success == len(all_files)
            
        except Exception as e:
            print(f"Error during directory deletion: {e}")
            return False
    
    def print_log(self) -> None:
        """Print deletion log."""
        self.logger.print_log()
