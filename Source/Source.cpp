#include <iostream>
#include "DESEncryption.h"
#include "DESDecryption.h"
#include "Padding.h"
#include <vector>
#include <string>
#include <iomanip>

template<size_t N>
void printHex(const std::bitset<N>& bs) {
    // Print as hex for easy comparison
    uint64_t val = bs.to_ullong();
    std::cout << std::hex << std::uppercase << val << "\n";
}

// Helper functions to convert between byte arrays and bitsets
std::bitset<64> bytesToBlock(const uint8_t* bytes) {
    uint64_t block = 0;
    for (int i = 0; i < 8; i++) {
        block = (block << 8) | bytes[i];
    }
    return std::bitset<64>(block);
}
// Convert a 64-bit block back to bytes (big-endian)
void blockToBytes(const std::bitset<64>& block, uint8_t* out) {
    uint64_t val = block.to_ullong();
    for (int i = 7; i >= 0; i--) {
        out[i] = val & 0xFF;
        val >>= 8;
    }
}

void testEncryptionDecryptionBlock() {
    std::bitset<64> plaintext(0x0123456789ABCDEFULL);
    std::bitset<64> key(0x0123456789ABCDEFULL);

    std::cout << "Plaintext:           "; printHex(plaintext);
    std::cout << "Key:                 "; printHex(key);

    std::bitset<48> subkeys[16];
    DES::keyExpansion(subkeys, key);
    std::bitset<64> ciphertext = DES::encrypt(plaintext, subkeys);

    std::cout << "Ciphertext:          "; printHex(ciphertext);
    std::cout << "Expected:            56CC09E7CFDC4CEF\n";

    if (ciphertext.to_ullong() == 0x56CC09E7CFDC4CEFULL) {
        std::cout << "Encryption PASSED\n";
    }
    else {
        std::cout << "Encryption FAILED\n";
    }

    std::bitset<64> decryptPlaintext = DES::decrypt(ciphertext, subkeys);

    std::cout << "\nPlaintext:           "; printHex(plaintext);
    std::cout << "Expected:            "; printHex(decryptPlaintext);

    if (decryptPlaintext.to_ullong() == plaintext.to_ullong()) {
        std::cout << "Decryption PASSED\n";
    }
    else {
        std::cout << "Decryption FAILED\n";
    }
}

void testMultiBlockWithPadding() {
    const std::string message = "Hello, DES!";
    std::bitset<64> key(0x0123456789ABCDEFULL);

    std::cout << "\nMessage:             " << message << "\n";

    std::bitset<48> subkeys[16];
    DES::keyExpansion(subkeys, key);

    // Encrypt
    std::vector<uint8_t> plainBytes(message.begin(), message.end());
    Padding::pkcs7Pad(plainBytes);

    std::cout << "Padded Plaintext:    ";
    for (uint8_t b : plainBytes) {
        std::cout << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << (int)b << " ";
    }
    std::cout << std::dec << "\n";

    std::vector<uint8_t> cipherBytes(plainBytes.size());
    for (size_t i = 0; i < plainBytes.size(); i += 8) {
        std::bitset<64> block = bytesToBlock(plainBytes.data() + i);
        blockToBytes(DES::encrypt(block, subkeys), cipherBytes.data() + i);
    }

    std::cout << "Ciphertext (hex):    ";
    for (uint8_t b : cipherBytes) {
        std::cout << std::hex << std::uppercase << (int)b << " ";
    }
    std::cout << std::dec << "\n";

    // Decrypt
    std::vector<uint8_t> decryptedBytes(cipherBytes.size());
    for (size_t i = 0; i < cipherBytes.size(); i += 8) {
        std::bitset<64> block = bytesToBlock(cipherBytes.data() + i);
        blockToBytes(DES::decrypt(block, subkeys), decryptedBytes.data() + i);
    }

    Padding::pkcs7Unpad(decryptedBytes);
    std::string recovered(decryptedBytes.begin(), decryptedBytes.end());

    std::cout << "Recovered:           " << recovered << "\n";
    if (recovered == message) {
        std::cout << "Padding PASSED\n";
    }
    else {
        std::cout << "Padding FAILED\n";
    }
}

// Test
int main() {
    testEncryptionDecryptionBlock();
    testMultiBlockWithPadding();

    return 0;
}