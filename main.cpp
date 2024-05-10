#include <iostream>

using std::cin;
using std::cout;
using std::endl;

#include "filesystem"

#include <string>

using std::string;

#include "rsa.h"

using CryptoPP::RSA;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;

#include "integer.h"

using CryptoPP::Integer;

#include "osrng.h"

using CryptoPP::AutoSeededRandomPool;

#include "filters.h"

using CryptoPP::StringSource;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::PK_DecryptorFilter;
using CryptoPP::StringSink;

#include "files.h"

using CryptoPP::FileSource;
using CryptoPP::FileSink;

#include "base64.h"

using CryptoPP::Base64Encoder;
using CryptoPP::Base64Decoder;

#include "pem.h"
#include "algparam.h"

using CryptoPP::AlgorithmParameters;
using CryptoPP::MakeParameters;

using CryptoPP::byte;

#include "gcm.h"
using CryptoPP::GCM;

#include "aes.h"
using CryptoPP::AES;

#include "secblockfwd.h"
using CryptoPP::SecByteBlock;

struct RSAKeyPair {
    RSA::PrivateKey privateKey;
    RSA::PublicKey publicKey;
};

enum KeySize {
    KEY_1024 = 1024,
    KEY_2048 = 2048,
    KEY_3072 = 3072,
    KEY_4096 = 4096
};

void generateAESKey(AutoSeededRandomPool &rng, byte *key) {
    SecByteBlock secByteBlock(AES::DEFAULT_KEYLENGTH);
    rng.GenerateBlock(key, sizeof key);
}

void GenerateKeyPair(AutoSeededRandomPool &rng, RSAKeyPair &keyPair, long keySize = 3072) {
    keyPair.privateKey.GenerateRandomWithKeySize(rng, keySize);
    keyPair.publicKey = RSA::PublicKey(keyPair.privateKey);
}

string EncryptMessage(const RSAKeyPair &keyPair, const string &message) {
    AutoSeededRandomPool rng;
    RSA::PublicKey publicKey = keyPair.publicKey;
    RSAES_OAEP_SHA_Encryptor encryptor(publicKey);

    string ciphertext;

    StringSource stringSource(message, true,
                              new PK_EncryptorFilter(rng, encryptor, new Base64Encoder(new StringSink(ciphertext))));

    return ciphertext;
}

string DecryptMessage(const RSAKeyPair &keyPair, const string &ciphertext) {
    AutoSeededRandomPool rng;
    RSA::PrivateKey privateKey = keyPair.privateKey;
    RSAES_OAEP_SHA_Decryptor decryptor(privateKey);

    string message;

    StringSource stringSource(ciphertext, true,
                              new Base64Decoder(new PK_DecryptorFilter(rng, decryptor, new StringSink(message))));

    return message;
}

[[maybe_unused]] bool isInteger(const std::string &s) {
    if (s.empty() || ((!isdigit(s[0])) && (s[0] != '-') && (s[0] != '+'))) return false;
    char *p;
    strtol(s.c_str(), &p, 10);
    return (*p == 0);
}

void printHelper() {
    cout << "Usage: " << endl;
    cout << "  Generate key pair: generate(gen|g) <keySize> <format> <outputDir>" << endl;
    cout << "      Example: g 3072 PEM keys" << endl;
    cout << "  Encrypt message: encrypt(enc|e) <publicKeyFile> <message>" << endl;
    cout << "      Example: e keys/public_key.pem message.txt" << endl;
    cout << "  Decrypt message: decrypt(dec|d) <privateKeyFile> <message>" << endl;
    cout << "      Example: d keys/private_key.pem ciphertext.txt" << endl;
}

int main(int argc, char **argv) {
    AutoSeededRandomPool rng;
    byte* key = new byte[AES::DEFAULT_KEYLENGTH];

    generateAESKey(rng, key);

    byte* keyCopy = new byte[AES::DEFAULT_KEYLENGTH];
    memcpy(keyCopy, key, AES::DEFAULT_KEYLENGTH);

    // Convert key to base64
    string keyBase64;
    Base64Encoder(new StringSink(keyBase64)).Put(key, sizeof key);

    cout << "base64 key: " << keyBase64 << endl;

    // Convert key to byte from base64
    byte* keyHexByte = new byte[AES::DEFAULT_KEYLENGTH];
    Base64Decoder decoder;

    decoder.Put((byte*) keyBase64.c_str(), keyBase64.size());
    decoder.MessageEnd();

    CryptoPP::word64 size = decoder.MaxRetrievable();
    cout << size << endl;

    if(size && size <= SIZE_MAX)
    {
        decoder.Get((byte*)keyHexByte, size);
    }

    cout << keyCopy << "|" << keyHexByte << endl;

    // Convert byte to base64
    string keyHexByteBase64;
    Base64Encoder(new StringSink(keyHexByteBase64)).Put(keyHexByte, sizeof keyHexByte);
    cout << "base64 key after: " << keyHexByteBase64 << endl;

    return 0;

//    if (argc == 1) {
//        printHelper();
//    }
//
//    string command = argv[1];
//
//    if (command == "generate" || command == "gen" || command == "g") {
//        // Generate key pair
//        AutoSeededRandomPool rng;
//        RSAKeyPair keyPair;
//        GenerateKeyPair(rng, keyPair, 3072);
//
//        string format = "PEM";
//        if (argv[3] != nullptr) {
//            format = argv[3];
//        }
//
//        if (format == "PEM") {
//            string currentDirectory = std::filesystem::current_path();
//            string outputDir = argv[4];
//
//            if (!std::filesystem::is_directory(outputDir)) {
//                cout << "Directory '" << outputDir << "' does not exist. Do you want to create it? (y/n)" << endl;
//
//                string answer;
//                std::cin >> answer;
//
//                if (answer == "y") {
//                    std::filesystem::create_directory(outputDir);
//                } else {
//                    return 1;
//                }
//            }
//
//            string privateKeyFileName = outputDir + "/privateKey.pem";
//            string publicKeyFileName = outputDir + "/publicKey.pem";
//
//            FileSink privateKeyFileSink(privateKeyFileName.c_str());
//            FileSink publicKeyFileSink(publicKeyFileName.c_str());
//
//            PEM_Save(privateKeyFileSink, keyPair.privateKey);
//            PEM_Save(publicKeyFileSink, keyPair.publicKey);
//        } else {
//            cout << "Invalid format: " << format << endl;
//        }
//
//        return 0;
//    } else if (command == "encrypt" || command == "enc" || command == "e") {
//        // Load key pair
//        string publicKeyFileName = argv[2];
//        string messageFileName = argv[3];
//
//        RSAKeyPair keyPair;
//        FileSource publicKeyFileSource(publicKeyFileName.c_str(), true);
//        PEM_Load(publicKeyFileSource, keyPair.publicKey);
//
//        // Encrypt message
//        string message;
//        FileSource messageFileSource(messageFileName.c_str(), true, new StringSink(message));
//        string cipherText = EncryptMessage(keyPair, message);
//
//        // Write encrypted message to file
//        string encryptedMessageFileName = messageFileName + ".enc";
//
//        StringSource stringSource(cipherText, true, new FileSink(encryptedMessageFileName.c_str()));
//
//        cout << "Encrypted message: " << cipherText << endl;
//        return 0;
//    } else if (command == "decrypt" || command == "dec" || command == "d") {
//        // Load key pair
//        string privateKeyFileName = argv[2];
//        string ciphertextFileName = argv[3];
//
//        RSAKeyPair keyPair;
//        FileSource privateKeyFileSource(privateKeyFileName.c_str(), true);
//        PEM_Load(privateKeyFileSource, keyPair.privateKey);
//
//        // Decrypt message
//        string ciphertext;
//        FileSource ciphertextFileSource(ciphertextFileName.c_str(), true, new StringSink(ciphertext));
//        string message = DecryptMessage(keyPair, ciphertext);
//
//        cout << "Decrypted message: " << message << endl;
//        return 0;
//    } else {
//        cout << "Invalid command: " << command << endl;
//        return 1;
//    }
}

