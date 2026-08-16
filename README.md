# AES File Encryptor

A command-line file encryption tool written in C++ that uses AES-256-CBC encryption via OpenSSL. Encrypt any file with a password, and decrypt it back with the same password.

## Features

- **AES-256-CBC encryption** — industry-standard cipher used by governments and banks
- **PBKDF2 key derivation** (100,000 iterations) — turns your password into a secure key and slows down brute-force attacks
- **Random salt + IV per file** — encrypting the same file twice with the same password produces different output each time, preventing pattern analysis
- **Password verification** — decrypting with the wrong password fails cleanly instead of producing garbage output

## How It Works

1. The program reads your input file as raw bytes
2. A random salt and IV (initialization vector) are generated
3. Your password + salt are run through PBKDF2-HMAC-SHA256 to derive a 256-bit encryption key
4. The file is encrypted using AES-256 in CBC mode
5. The salt, IV, and encrypted data are written to the output file (salt and IV don't need to stay secret — they just need to be unique)

To decrypt, the same salt and IV are read back from the file, the key is re-derived from your password, and the reverse operation is performed.

## Requirements

- g++ (C++ compiler)
- OpenSSL development libraries

On Debian/Kali-based systems:
```bash
sudo apt update
sudo apt install libssl-dev
```

## Build

```bash
g++ -o aes_encryptor aes_encryptor.cpp -lssl -lcrypto -Wall
```

## Usage

**Encrypt a file:**
```bash
./aes_encryptor -e <input_file> <output_file> <password>
```

**Decrypt a file:**
```bash
./aes_encryptor -d <input_file> <output_file> <password>
```

**Example:**
```bash
./aes_encryptor -e secret.txt secret.aes MyStrongPassword123
./aes_encryptor -d secret.aes secret_decrypted.txt MyStrongPassword123
```

## Security Notes

This project was built for learning purposes as part of my cybersecurity self-study. While it uses real, industry-standard cryptography (AES-256-CBC + PBKDF2), a few things to keep in mind:

- Password strength matters — a weak password makes brute-forcing easier regardless of the encryption strength behind it
- This tool does not manage or store passwords for you
- For production use cases, authenticated encryption modes (like AES-GCM) are generally preferred over CBC, since they also verify data integrity

## About

Built by Micheal as part of a self-directed cybersecurity and ethical hacking learning path, focused on understanding cryptography fundamentals from the ground up rather than just using pre-built libraries as a black box.
