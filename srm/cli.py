"""Command-line interface for srm."""

import sys
import os
import argparse
from pathlib import Path

from srm.config import SecureDeletionConfig
from srm.core.deleter import SecureFileDeleter


def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Secure RM (srm) - Cryptographically secure file deletion",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  srm file.txt                    # Secure delete with defaults
  srm -v -p 5 sensitive.doc       # Verbose mode, 5 overwrite passes
  srm --chacha20 secret.pdf       # Use ChaCha20 encryption
  srm file1.txt file2.txt         # Delete multiple files
  srm -r mydir                    # Recursively delete directory
  srm -r -v -f logs/ temp/        # Force delete multiple directories
  srm --log results.csv           # Enable secure logging
        """
    )
    
    parser.add_argument('files', nargs='+', 
                       help='File(s) or directory(ies) to securely delete')
    parser.add_argument('-r', '--recursive', action='store_true',
                       help='Recursively delete directories')
    parser.add_argument('-p', '--passes', type=int, default=3,
                       help='Number of overwrite passes (default: 3)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('--chacha20', action='store_true',
                       help='Use ChaCha20 instead of AES-256')
    parser.add_argument('--no-metadata', action='store_true',
                       help='Skip metadata sanitization [Not recommended]')
    parser.add_argument('--log', action='store_true',
                       help='Enable secure deletion logging')
    parser.add_argument('-f', '--force', action='store_true',
                       help='Force deletion without confirmation')
    
    return parser.parse_args()


def confirm_deletion(files: list, recursive: bool) -> bool:
    """Prompt user for confirmation.
    
    Args:
        files: List of files/directories to delete
        recursive: Whether recursive deletion is enabled
        
    Returns:
        True if user confirms
    """
    file_count = 0
    dir_count = 0
    
    for item in files:
        p = Path(item)
        if p.is_dir():
            dir_count += 1
            if recursive:
                for root, dirs, files_in_dir in os.walk(p):
                    file_count += len(files_in_dir)
        elif p.is_file():
            file_count += 1
    
    msg = "WARNING: This will PERMANENTLY delete "
    if file_count > 0:
        msg += f"{file_count} file(s)"
    if dir_count > 0:
        if file_count > 0:
            msg += " and "
        msg += f"{dir_count} directory(ies)"
    msg += "."
    
    print(msg)
    response = input("Are you sure? (yes/no): ")
    return response.lower() in ['yes', 'y']


def main():
    """Main entry point for srm command."""
    args = parse_arguments()
    
    # Validate passes
    if args.passes < 1 or args.passes > 35:
        print("Error: Number of passes must be between 1 and 35")
        sys.exit(1)
    
    # Confirmation prompt
    if not args.force:
        if not confirm_deletion(args.files, args.recursive):
            print("Operation cancelled.")
            sys.exit(0)
    
    # Configure secure deletion
    config = SecureDeletionConfig(
        overwrite_passes=args.passes,
        use_chacha20=args.chacha20,
        sanitize_metadata=not args.no_metadata,
        secure_log=args.log,
        verbose=args.verbose
    )
    
    deleter = SecureFileDeleter(config)
    
    # Process each file/directory
    success_count = 0
    total_items = len(args.files)
    
    for item in args.files:
        path = Path(item)
        
        if path.is_file():
            if deleter.secure_delete(item):
                success_count += 1
        elif path.is_dir():
            if not args.recursive:
                print(f"Error: '{item}' is a directory. Use -r to delete directories.")
                continue
            
            if deleter.secure_delete_directory(item):
                success_count += 1
        else:
            print(f"Error: '{item}' not found or unsupported type")
    
    # Print summary
    print(f"\n{'='*60}")
    print(f"Deletion Summary:")
    print(f"  Items processed: {success_count}/{total_items}")
    print(f"  Files deleted: {deleter.files_processed}")
    print(f"  Directories removed: {deleter.dirs_processed}")
    print(f"{'='*60}")
    
    # Print log if enabled
    if args.log:
        deleter.print_log()
    
    sys.exit(0 if success_count == total_items else 1)


if __name__ == "__main__":
    main()
