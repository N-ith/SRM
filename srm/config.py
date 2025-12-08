"""Configuration management for secure deletion operations."""

from dataclasses import dataclass


@dataclass
class SecureDeletionConfig:
    """Configuration for secure deletion operations.
    
    Attributes:
        overwrite_passes: Number of overwrite passes (1-35)
        use_chacha20: Use ChaCha20 instead of AES-256
        sanitize_metadata: Enable metadata sanitization
        secure_log: Enable secure deletion logging
        verbose: Enable verbose output
    """
    overwrite_passes: int = 3
    use_chacha20: bool = False
    sanitize_metadata: bool = True
    secure_log: bool = False
    verbose: bool = False
    
    def validate(self) -> None:
        """Validate configuration parameters."""
        if not 1 <= self.overwrite_passes <= 35:
            raise ValueError("overwrite_passes must be between 1 and 35")
