#include <iostream>
#include "aes_file_encryption.h"

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "使用方法: " << argv[0] << " <encrypt/decrypt> <input_file> <output_file>\n";
        return 1;
    }

    std::string mode = argv[1];
    std::string inputFile = argv[2];
    std::string outputFile = argv[3];

    try {
        std::string key = AESFileEncryption::generateRandomKey();
        AESFileEncryption aes(key);

        if (mode == "encrypt") {
            aes.encryptFile(inputFile, outputFile);
            std::cout << "文件已加密，保存为: " << outputFile << std::endl;
            std::cout << "使用的密钥（请妥善保存）: " << key << std::endl;
        } else if (mode == "decrypt") {
            aes.decryptFile(inputFile, outputFile);
            std::cout << "文件已解密，保存为: " << outputFile << std::endl;
        } else {
            std::cerr << "无效的操作模式! 使用 'encrypt' 或 'decrypt'.\n";
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "错误: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
