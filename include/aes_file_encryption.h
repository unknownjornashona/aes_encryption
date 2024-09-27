#ifndef AES_FILE_ENCRYPTION_H
#define AES_FILE_ENCRYPTION_H

#include <string>

class AESFileEncryption {
public:
    AESFileEncryption(const std::string& key);
    
    // 文件加密
    void encryptFile(const std::string& inputFile, const std::string& outputFile);
    
    // 文件解密
    void decryptFile(const std::string& inputFile, const std::string& outputFile);
    
    // 随机生成密钥
    static std::string generateRandomKey();

private:
    std::string key;
    
    void handleErrors();
};

#endif // AES_FILE_ENCRYPTION_H
