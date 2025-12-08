# Secure RM (srm) - Cryptographically Secure File Deletion

A professional-grade secure file deletion tool with cryptographic guarantees.

## Features

- **One-time encryption** with ephemeral AES-256 or ChaCha20 keys
- **Multiple overwrite passes** using cryptographic random data
- **Metadata sanitization** (timestamp randomization, filename obfuscation)
- **Recursive directory deletion**
- **Secure logging** with SHA-256 path hashing
- **Clean code architecture** with separation of concerns

## Installation

```bash
# Clone the repository
git clone https://github.com/N-ith/SRM.git
cd SRM

# Install requirement
pip install requirement.txt

# Install in development mode
pip install -e .

# Or install from source
python setup.py install
```

## OR 
```
#For quick testing only
git clone https://github.com/N-ith/SRM.git
cd SRM

# Install requirement
pip install requirement.txt

python3 -m srm.cli [option(s)] <path_to_your_file>
```

## Usage

```bash
# Basic file deletion
srm file.txt

# Recursive directory deletion
srm -r mydir/

# Advanced options
srm -v -p 7 --chacha20 --log sensitive_data.pdf

# Multiple files/directories
srm -r build/ dist/ *.log

# Force delete without confirmation
srm -f -r temp/
```

## Command-Line Options

- `-r, --recursive`: Recursively delete directories
- `-p, --passes N`: Number of overwrite passes (1-35, default: 3)
- `-v, --verbose`: Enable verbose output
- `--chacha20`: Use ChaCha20 instead of AES-256
- `--no-metadata`: Skip metadata sanitization
- `--log`: Enable secure deletion logging
- `-f, --force`: Skip confirmation prompt

## Architecture

The project follows clean code principles with clear separation:

- `crypto/`: Cryptographic operations (encryption, pattern generation)
- `core/`: Core deletion logic (orchestration, file operations)
- `metadata/`: Metadata sanitization
- `utils/`: Logging and validation utilities
- `cli.py`: Command-line interface

## Security Guarantees

1. **Encryption Layer**: Files encrypted with ephemeral keys (never stored)
2. **Overwrite Layer**: Multiple passes with cryptographic random data
3. **Metadata Layer**: Timestamps randomized, filenames obfuscated
4. **Unlinking Layer**: Final filesystem deletion

Even if overwriting fails, encrypted data cannot be recovered without the key.

## Uninstall

```bash
# Uninstall
pip uninstall srm
```
