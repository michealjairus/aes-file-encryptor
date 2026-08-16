// AES-256-CBC File Encryptor/Decryptor using OpenSSL
// Compile with: g++ -o aes_encryptor aes_encryptor.cpp -lssl -lcrypto
//
// Usage:
//   Encrypt: ./aes_encryptor -e <input_file> <output_file> <password>
//   Decrypt: ./aes_encryptor -d <input_file> <output_file> <password>

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

const int SALT_LEN = 8;
const int KEY_LEN = 32;   // 256 bits for AES-256
const int IV_LEN = 16;    // AES block size
const int ITERATIONS = 100000; // PBKDF2 iterations - slows down brute force attacks

std::vector<unsigned char> readFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) throw std::runtime_error("Could not open file: " + path);
    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<unsigned char> buffer(size);
    file.read(reinterpret_cast<char*>(buffer.data()), size);
    return buffer;
}

void writeFile(const std::string& path, const std::vector<unsigned char>& data) {
    std::ofstream file(path, std::ios::binary);
    if (!file) throw std::runtime_error("Could not write file: " + path);
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}

void printOpenSSLError() {
    unsigned long err = ERR_get_error();
    char errBuf[256];
    ERR_error_string_n(err, errBuf, sizeof(errBuf));
    std::cerr << "OpenSSL error: " << errBuf << "\n";
}

// Derives a 256-bit key from the password + salt using PBKDF2
bool deriveKey(const std::string& password, const unsigned char* salt, unsigned char* key) {
    int result = PKCS5_PBKDF2_HMAC(
        password.c_str(), password.length(),
        salt, SALT_LEN,
        ITERATIONS,
        EVP_sha256(),
        KEY_LEN, key
    );
    return result == 1;
}

std::vector<unsigned char> encrypt(const std::vector<unsigned char>& plaintext,
                                     const unsigned char* key, const unsigned char* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create cipher context");

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EncryptInit failed");
    }

    std::vector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int len = 0, ciphertextLen = 0;

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EncryptUpdate failed");
    }
    ciphertextLen = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EncryptFinal failed");
    }
    ciphertextLen += len;

    ciphertext.resize(ciphertextLen);
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

std::vector<unsigned char> decrypt(const std::vector<unsigned char>& ciphertext,
                                     const unsigned char* key, const unsigned char* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create cipher context");

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("DecryptInit failed");
    }

    std::vector<unsigned char> plaintext(ciphertext.size());
    int len = 0, plaintextLen = 0;

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("DecryptUpdate failed");
    }
    plaintextLen = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("DecryptFinal failed - wrong password or corrupted file");
    }
    plaintextLen += len;

    plaintext.resize(plaintextLen);
    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

void printUsage(const char* progName) {
    std::cout << "AES-256 File Encryptor/Decryptor\n\n";
    std::cout << "Usage:\n";
    std::cout << "  Encrypt: " << progName << " -e <input_file> <output_file> <password>\n";
    std::cout << "  Decrypt: " << progName << " -d <input_file> <output_file> <password>\n\n";
    std::cout << "Example:\n";
    std::cout << "  " << progName << " -e secret.txt secret.aes MyStrongPassword123\n";
    std::cout << "  " << progName << " -d secret.aes secret.txt MyStrongPassword123\n";
}

int main(int argc, char* argv[]) {
    if (argc != 5) {
        printUsage(argv[0]);
        return 1;
    }

    std::string mode = argv[1];
    std::string inputPath = argv[2];
    std::string outputPath = argv[3];
    std::string password = argv[4];

    if (mode != "-e" && mode != "-d") {
        std::cerr << "Error: mode must be -e (encrypt) or -d (decrypt)\n";
        printUsage(argv[0]);
        return 1;
    }

    if (password.empty()) {
        std::cerr << "Error: password cannot be empty.\n";
        return 1;
    }

    try {
        if (mode == "-e") {
            std::cout << "Reading " << inputPath << "...\n";
            std::vector<unsigned char> plaintext = readFile(inputPath);
            std::cout << "Read " << plaintext.size() << " bytes.\n";

            unsigned char salt[SALT_LEN];
            unsigned char iv[IV_LEN];
            if (RAND_bytes(salt, SALT_LEN) != 1 || RAND_bytes(iv, IV_LEN) != 1) {
                throw std::runtime_error("Failed to generate random salt/IV");
            }

            unsigned char key[KEY_LEN];
            std::cout << "Deriving key from password (this takes a moment by design)...\n";
            if (!deriveKey(password, salt, key)) {
                throw std::runtime_error("Key derivation failed");
            }

            std::cout << "Encrypting...\n";
            std::vector<unsigned char> ciphertext = encrypt(plaintext, key, iv);

            std::vector<unsigned char> output;
            output.insert(output.end(), salt, salt + SALT_LEN);
            output.insert(output.end(), iv, iv + IV_LEN);
            output.insert(output.end(), ciphertext.begin(), ciphertext.end());

            writeFile(outputPath, output);
            std::cout << "Done! Encrypted " << plaintext.size() << " bytes -> "
                      << output.size() << " bytes written to " << outputPath << "\n";

        } else {
            std::cout << "Reading " << inputPath << "...\n";
            std::vector<unsigned char> input = readFile(inputPath);

            if (input.size() < SALT_LEN + IV_LEN) {
                throw std::runtime_error("File too small to be a valid encrypted file");
            }

            unsigned char salt[SALT_LEN];
            unsigned char iv[IV_LEN];
            std::memcpy(salt, input.data(), SALT_LEN);
            std::memcpy(iv, input.data() + SALT_LEN, IV_LEN);

            std::vector<unsigned char> ciphertext(
                input.begin() + SALT_LEN + IV_LEN, input.end()
            );

            unsigned char key[KEY_LEN];
            std::cout << "Deriving key from password...\n";
            if (!deriveKey(password, salt, key)) {
                throw std::runtime_error("Key derivation failed");
            }

            std::cout << "Decrypting...\n";
            std::vector<unsigned char> plaintext = decrypt(ciphertext, key, iv);

            writeFile(outputPath, plaintext);
            std::cout << "Done! Decrypted to " << outputPath << " (" << plaintext.size() << " bytes)\n";
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}