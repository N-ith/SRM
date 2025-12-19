"""Command-line interface for srm."""

import sys
import os
import argparse
from pathlib import Path

from srm.deleter import SecureFileDeleter


def main():
    """Main entry point for srm command."""
    parser = argparse.ArgumentParser(
        prog="srm",
        description="Secure file deletion with cryptographic guarantees",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  srm file.txt                 # Delete file (3 passes, AES-256)
  srm -v -p 7 secret.pdf       # 7 passes, verbose output
  srm --chacha20 data.zip      # Use ChaCha20 encryption
  srm -r project/              # Recursively delete directory
  srm -f -r logs/ temp/        # Force delete multiple directories
  srm --log sensitive.doc      # Enable secure logging
        """
    )
    
    parser.add_argument('files', nargs='+', help='Files/directories to delete')
    parser.add_argument('-r', '--recursive', action='store_true',
                       help='Delete directories recursively')
    parser.add_argument('-p', '--passes', type=int, default=3,
                       help='Overwrite passes (default: 3, max: 35)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    parser.add_argument('--chacha20', action='store_true',
                       help='Use ChaCha20 instead of AES-256')
    parser.add_argument('--no-sanitize', action='store_true',
                       help='Skip metadata sanitization [Not recommended!]')
    parser.add_argument('--log', action='store_true',
                       help='Enable deletion logging')
    parser.add_argument('-f', '--force', action='store_true',
                       help='No confirmation prompt')
    
    args = parser.parse_args()
    
    # Validate passes
    if not 1 <= args.passes <= 35:
        print("Error: Passes must be between 1 and 35")
        sys.exit(1)
    
    # Confirmation
    if not args.force:
        file_count = sum(1 for f in args.files if Path(f).is_file())
        dir_count = sum(1 for f in args.files if Path(f).is_dir())
        
        if dir_count > 0 and args.recursive:
            for d in args.files:
                if Path(d).is_dir():
                    for _, _, files in os.walk(d):
                        file_count += len(files)
        
        print(f"WARNING: Permanently delete {file_count} file(s) and {dir_count} dir(s)?")
        if input("Continue? (yes/no): ").lower() not in ['yes', 'y']:
            print("Cancelled.")
            sys.exit(0)
    
    # Create deleter
    deleter = SecureFileDeleter(
        passes=args.passes,
        use_chacha20=args.chacha20,
        sanitize=not args.no_sanitize,
        log=args.log,
        verbose=args.verbose
    )
    
    # Process items
    success = 0
    for item in args.files:
        path = Path(item)
        
        if path.is_file():
            if deleter.delete_file(item):
                success += 1
        elif path.is_dir():
            if not args.recursive:
                print(f"Error: '{item}' is a directory. Use -r flag.")
                continue
            if deleter.delete_directory(item):
                success += 1
        else:
            print(f"Error: '{item}' not found")
    
    # Summary
    print(f"\n{'='*50}")
    print(f"Files deleted: {deleter.files_deleted}")
    print(f"Directories removed: {deleter.dirs_deleted}")
    print(f"Success: {success}/{len(args.files)}")
    print(f"{'='*50}")
    
    if args.log:
        deleter.print_log()
    
    sys.exit(0 if success == len(args.files) else 1)


if __name__ == "__main__":
    main()
