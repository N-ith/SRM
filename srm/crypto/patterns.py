"""Overwrite pattern generation for secure deletion."""

import secrets
from enum import Enum
from typing import Union


class PatternType(Enum):
    """Types of overwrite patterns."""
    RANDOM = "random"
    ZEROS = "zeros"
    ONES = "ones"
    ALTERNATING = "alternating"


class OverwritePattern:
    """Generates secure overwrite patterns for file deletion."""
    
    @staticmethod
    def generate(size: int, pattern_type: Union[PatternType, str] = PatternType.RANDOM) -> bytes:
        """Generate overwrite pattern of specified size.
        
        Args:
            size: Size of pattern in bytes
            pattern_type: Type of pattern to generate
            
        Returns:
            Generated pattern as bytes
        """
        if isinstance(pattern_type, str):
            pattern_type = PatternType(pattern_type)
        
        if pattern_type == PatternType.RANDOM:
            return secrets.token_bytes(size)
        elif pattern_type == PatternType.ZEROS:
            return b'\x00' * size
        elif pattern_type == PatternType.ONES:
            return b'\xff' * size
        elif pattern_type == PatternType.ALTERNATING:
            return bytes([0xAA if i % 2 == 0 else 0x55 for i in range(size)])
        else:
            return secrets.token_bytes(size)
    
    @staticmethod
    def get_default_sequence() -> list[PatternType]:
        """Get default sequence of overwrite patterns.
        
        Returns:
            List of pattern types for multiple passes
        """
        return [
            PatternType.RANDOM,
            PatternType.ZEROS,
            PatternType.ONES,
            PatternType.ALTERNATING,
            PatternType.RANDOM,
        ]