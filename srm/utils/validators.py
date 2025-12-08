"""Input validation utilities."""

from pathlib import Path


class PathValidator:
    """Validates file and directory paths."""
    
    @staticmethod
    def validate_file(file_path: str) -> bool:
        """Check if path is a valid file.
        
        Args:
            file_path: Path to validate
            
        Returns:
            True if valid file
        """
        path = Path(file_path)
        return path.exists() and path.is_file()
    
    @staticmethod
    def validate_directory(dir_path: str) -> bool:
        """Check if path is a valid directory.
        
        Args:
            dir_path: Path to validate
            
        Returns:
            True if valid directory
        """
        path = Path(dir_path)
        return path.exists() and path.is_dir()
    
    @staticmethod
    def validate_passes(passes: int) -> bool:
        """Validate number of overwrite passes.
        
        Args:
            passes: Number of passes
            
        Returns:
            True if valid (1-35)
        """
        return 1 <= passes <= 35