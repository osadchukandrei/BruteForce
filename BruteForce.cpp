#include <string>
#include <vector>
#include <fstream>
#include <exception>
#include <iostream>

#include "openssl/evp.h"
#include <openssl/aes.h>
#include "openssl/sha.h"

unsigned char key[EVP_MAX_KEY_LENGTH];
unsigned char iv[EVP_MAX_IV_LENGTH];
size_t sizeHash = 0;


void ReadFile(const std::string& filePath, std::vector<unsigned char>& buf)
{
    std::basic_fstream<unsigned char> fileStream(filePath, std::ios::binary | std::fstream::in);
    if (!fileStream.is_open())
    {
        throw std::runtime_error("Can not open file " + filePath);
    }

    buf.clear();
    buf.insert(buf.begin(), std::istreambuf_iterator<unsigned char>(fileStream), std::istreambuf_iterator<unsigned char>());
    fileStream.close();
}

void WriteFile(const std::string& filePath, const std::vector<unsigned char>& buf)
{
    std::basic_ofstream<unsigned char> fileStream(filePath, std::ios::binary);
    fileStream.write(&buf[0], buf.size());
    fileStream.close();
}

void AppendToFile(const std::string& filePath, const std::vector<unsigned char>& buf)
{
    std::basic_ofstream<unsigned char> fileStream(filePath, std::ios::binary | std::ios::app);
    fileStream.write(&buf[0], buf.size());
    fileStream.close();
}

void PasswordToKey(std::string& password)
{
    const EVP_MD* dgst = EVP_get_digestbyname("md5");
    if (!dgst)
    {
        throw std::runtime_error("no such digest");
    }

    const unsigned char* salt = NULL;
    if (!EVP_BytesToKey(EVP_aes_128_cbc(), EVP_md5(), salt,
        reinterpret_cast<unsigned char*>(&password[0]),
        password.size(), 1, key, iv))
    {
        throw std::runtime_error("EVP_BytesToKey failed");
    }
}

void EncryptAes(const std::vector<unsigned char> plainText, std::vector<unsigned char>& chipherText)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
    {
        throw std::runtime_error("EncryptInit error");
    }

    std::vector<unsigned char> chipherTextBuf(plainText.size() + AES_BLOCK_SIZE);
    int chipherTextSize = 0;
    if (!EVP_EncryptUpdate(ctx, &chipherTextBuf[0], &chipherTextSize, &plainText[0], plainText.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encrypt error");
    }

    int lastPartLen = 0;
    if (!EVP_EncryptFinal_ex(ctx, &chipherTextBuf[0] + chipherTextSize, &lastPartLen)) {       
        throw std::runtime_error("EncryptFinal error");
    }
    chipherTextSize += lastPartLen;
    chipherTextBuf.erase(chipherTextBuf.begin() + chipherTextSize, chipherTextBuf.end());

    chipherText.swap(chipherTextBuf);

    EVP_CIPHER_CTX_free(ctx);
}

void CalculateHash(const std::vector<unsigned char>& data, std::vector<unsigned char>& hash)
{
    std::vector<unsigned char> hashTmp(SHA256_DIGEST_LENGTH);

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, &data[0], data.size());
    SHA256_Final(&hashTmp[0], &sha256);

    hash.swap(hashTmp);
}

void Encrypt()
{
    std::vector<unsigned char> plainTextEn;
    ReadFile("plain_text.txt", plainTextEn);

    std::vector<unsigned char> hash;
    CalculateHash(plainTextEn, hash);

    sizeHash = hash.size();

    std::vector<unsigned char> chipherTextEn;
    EncryptAes(plainTextEn, chipherTextEn);

    WriteFile("chipher_text.txt", chipherTextEn);

    AppendToFile("chipher_text.txt", hash);
}

void DecryptAes(const std::vector<unsigned char> chipherText, std::vector<unsigned char> &plainText) { 
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
    {
        throw std::runtime_error("DecryptInit error");
    }
    
    std::vector<unsigned char> plainTextBuf(chipherText.size() );
    int plainTextSize = 0;
    if (!EVP_DecryptUpdate(ctx, &plainTextBuf[0], &plainTextSize, &chipherText[0], chipherText.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Decrypt error");
    }

    int lastPartLen = 0;
    if (!EVP_DecryptFinal_ex(ctx, &plainTextBuf[0] + plainTextSize, &lastPartLen)) { 
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("DecryptFinal error");
    }
    plainTextSize += lastPartLen;
    plainTextBuf.erase(plainTextBuf.begin() + plainTextSize, plainTextBuf.end());

    plainText.swap(plainTextBuf);

    EVP_CIPHER_CTX_free(ctx);

}

void DetachmentHash(std::vector<unsigned char> & chipherText,size_t sizeHash) {
    size_t newSizeChipherText = chipherText.size() - sizeHash;
    chipherText.erase(chipherText.begin()+newSizeChipherText,chipherText.end());
}

void Decrypt() {
    std::vector<unsigned char> chipherTextDe;
    ReadFile("chipher_text.txt", chipherTextDe);

    DetachmentHash(chipherTextDe, sizeHash);

    std::vector<unsigned char> plainTextDe;
    DecryptAes(chipherTextDe, plainTextDe);

    WriteFile("plain_text111.txt", plainTextDe);
}

int main()
{
    OpenSSL_add_all_digests();
   //OpenSSL_add_all_ciphers();
    
    std::string pass = "pass";
    try
    {
        PasswordToKey(pass);
        Encrypt();
        Decrypt();
    }
    catch (const std::runtime_error& ex)
    {
        std::cerr << ex.what();
    }
}