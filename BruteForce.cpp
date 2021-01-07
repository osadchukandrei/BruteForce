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

std::vector<unsigned char> HashDe;
std::vector<unsigned char> HashEn;
std::string pathFile;

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

void AppendToFile(const std::string& filePath, const std::string& passw)
{
    std::fstream fileStream(filePath, std::ios::binary | std::ios::app);
    fileStream.write(&passw[0], passw.size());
    fileStream.close();
}

void CreateFile(const std::string& filePath) {
    std::basic_ofstream<unsigned char> fileStream(filePath, std::ios::binary);
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

void CalculateHash(const std::vector<unsigned char>& data, std::vector<unsigned char>& hash)
{
    std::vector<unsigned char> hashTmp(SHA256_DIGEST_LENGTH);
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, &data[0], data.size());
    SHA256_Final(&hashTmp[0], &sha256);
    hash.swap(hashTmp);
}

void DecryptAes(const std::vector<unsigned char> chipherText, std::vector<unsigned char>& plainText) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
    {
        throw std::runtime_error("DecryptInit error");
    }

    std::vector<unsigned char> plainTextBuf(chipherText.size());
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

void CompareHashes(std::vector<unsigned char>& hashDe, std::vector<unsigned char>& hashEn) {
    if (hashDe != hashEn) {
        throw std::runtime_error("Hashes not equal");
    }
}

void DetachmentHash(std::vector<unsigned char>& chipherText, size_t sizeHash) {
    HashEn = chipherText;
    HashEn.erase(HashEn.begin(), HashEn.begin() + HashEn.size() - sizeHash);//hash
    size_t newSizeChipherText = chipherText.size() - sizeHash;
    chipherText.erase(chipherText.begin() + newSizeChipherText, chipherText.end());
}

void Decrypt(std::string password, std::vector<unsigned char>& chipherBuf) {

    std::vector<unsigned char> plainTextDe;
    DecryptAes(chipherBuf, plainTextDe);

    AppendToFile("logPasswords.txt", password);
    WriteFile("plain_text111.txt", plainTextDe);
}

void OpenChipherFile(int argc, char* argv[]) {
    switch (argc) {
    case 2:
        pathFile = argv[1];
        break;
    case 3:
        pathFile = argv[1];
        CreateFile("logPasswords.txt");
        break;
    default:
        throw std::runtime_error("not parameters");
    }
}

int main(int argc, char* argv[]) {

    OpenSSL_add_all_digests();
    std::string pass = "pass";    
    std::vector<unsigned char> chipherText;
    try
    {
        OpenChipherFile(argc, argv);
        ReadFile(pathFile, chipherText);
        PasswordToKey(pass);
        DetachmentHash(chipherText, HashEn.size());
        Decrypt(pass, chipherText);
    }
    catch (const std::runtime_error& ex)
    {
        std::cerr << ex.what();
    }
}