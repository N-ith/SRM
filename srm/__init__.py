"""Secure RM - Cryptographically secure file deletion tool."""

__version__ = "1.0.0"
__author__ = "Your Name"

from srm.config import SecureDeletionConfig
from srm.core.deleter import SecureFileDeleter

__all__ = ["SecureDeletionConfig", "SecureFileDeleter"]