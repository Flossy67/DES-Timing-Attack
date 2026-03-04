#include <iostream>
#include "DESEncryption.h"

template<size_t N>
void printBitset(const std::bitset<N>& bs) {
    // Print bitset from MSB to LSB 
    for (int i = N - 1; i >= 0; i--)
        std::cout << bs[i];
    std::cout << "\n";
}

template<size_t N>
void printHex(const std::bitset<N>& bs) {
    // Print as hex for easy comparison
    uint64_t val = bs.to_ullong();
    std::cout << std::hex << std::uppercase << val << "\n";
}

// Test
int main() {
    std::bitset<64> plaintext(0x0123456789ABCDEFULL);
    std::bitset<64> key(0x0123456789ABCDEFULL);

    std::cout << "Plaintext:           "; printHex(plaintext);
    std::cout << "Key:                 "; printHex(key);

    std::bitset<64> ciphertext = DES::encrypt(plaintext, key);

    std::cout << "Ciphertext:          "; printHex(ciphertext);
    std::cout << "Expected:            56CC09E7CFDC4CEF\n";

    if (ciphertext.to_ullong() == 0x56CC09E7CFDC4CEFULL)
        std::cout << "\nTest PASSED\n";
    else
        std::cout << "\nTest FAILED\n";

    return 0;
}