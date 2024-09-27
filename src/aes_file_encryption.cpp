#include "aes_file_encryption.h"
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <ctime>
#include <openssl/err.h>
#include <openssl/ssl.h>

// 日志文件路径
const std::string LOG_FILE = "encryption_log.txt";

AESFileEncryption::AESFileEncryption(const std::string& key) : key(key) {
    if (key.size() != AES_BLOCK_SIZE) {
        throw std::invalid_argument("Key must be exactly 16 bytes (128 bits) long.");
    }
}

std::string AESFileEncryption::generateRandomKey() {
    unsigned char buffer[AES_BLOCK_SIZE];
    if (!RAND_bytes(buffer, sizeof(buffer))) {
        throw std::runtime_error("Unable to generate random key.");
    }
    return std::string(reinterpret_cast<char*>(buffer), AES_BLOCK_SIZE);
}

void AESFileEncryption::encryptFile(const std::string& inputFile, const std::string& outputFile) {
    std::ifstream in(inputFile, std::ios::binary);
    std::ofstream out(outputFile, std::ios::binary);
    std::ofstream log(LOG_FILE, std::ios::app);

    if (!in.is_open() || !out.is_open() || !log.is_open()) {
        throw std::runtime_error("Unable to open files for encryption.");
    }

    unsigned char iv[AES_BLOCK_SIZE];
    if (!RAND_bytes(iv, sizeof(iv))) {
        handleErrors();
    }
    
    out.write(reinterpret_cast<char*>(iv), AES_BLOCK_SIZE); // 写入IV

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, reinterpret_cast<const unsigned char*>(key.c_str()), iv);
    
    unsigned char buffer[1024];
    unsigned char ciphertext[1024 + AES_BLOCK_SIZE];
    int outlen;

    while (in.read(reinterpret_cast<char*>(buffer), sizeof(buffer))) {
        EVP_EncryptUpdate(ctx, ciphertext, &outlen, buffer, in.gcount());
        out.write(reinterpret_cast<char*>(ciphertext), outlen);
    }

    EVP_EncryptFinal_ex(ctx, ciphertext, &outlen);
    out.write(reinterpret_cast<char*>(ciphertext), outlen);

    EVP_CIPHER_CTX_free(ctx);
    in.close();
    out.close();

    // 记录日志
    log << "[INFO] " << std::time(nullptr) << " - Encrypted file: " << inputFile << " to " << outputFile << std::endl;
    log.close();
}

void AESFileEncryption::decryptFile(const std::string& inputFile, const std::string& outputFile) {
    std::ifstream in(inputFile, std::ios::binary);
    std::ofstream out(outputFile, std::ios::binary);
    std::ofstream log(LOG_FILE, std::ios::app);

    if (!in.is_open() || !out.is_open() || !log.is_open()) {
        throw std::runtime_error("Unable to open files for decryption.");
    }

    unsigned char iv[AES_BLOCK_SIZE];
    in.read(reinterpret_cast<char*>(iv), AES_BLOCK_SIZE); // 读取IV
    if (in.gcount() != AES_BLOCK_SIZE) {
        throw std::runtime_error("Failed to read IV.");
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, reinterpret_cast<const unsigned char*>(key.c_str()), iv)) {
        handleErrors();
    }

    unsigned char buffer[1024];
    unsigned char plaintext[1024 + AES_BLOCK_SIZE];
    int outlen;

    while (in.read(reinterpret_cast<char*>(buffer), sizeof(buffer))) {
        if (EVP_DecryptUpdate(ctx, plaintext, &outlen, buffer, in.gcount()) != 1) {
            handleErrors();
        }
        out.write(reinterpret_cast<char*>(plaintext), outlen);
    }

    // 处理最后的块
    if (EVP_DecryptFinal_ex(ctx, plaintext + outlen, &outlen) > 0) {
        out.write(reinterpret_cast<char*>(plaintext), outlen);
    } else {
        handleErrors();
    }

    EVP_CIPHER_CTX_free(ctx);
    in.close();
    out.close();

    // 记录日志
    log << "[INFO] " << std::time(nullptr) << " - Decrypted file: " << inputFile << " to " << outputFile << std::endl;
    log.close();
}




void AESFileEncryption::handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}
