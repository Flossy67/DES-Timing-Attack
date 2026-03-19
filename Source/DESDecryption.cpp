#include "DESDecryption.h"

std::bitset<64> DES::decrypt(const std::bitset<64>& ciphertext, const std::bitset<48> subkeys[16]) {
	std::bitset<64> block;
	for (int i = 0; i < 64; i++) {
		block[63 - i] = ciphertext[64 - IP[i]];
	}

	std::bitset<32> left = block.to_ullong() >> 32;
	std::bitset<32> right = block.to_ullong() & 0xFFFFFFFF;

	for (int round = 0; round < 16; round++) {
		std::bitset<32> temp = right;
		right = left ^ fFunction(right, subkeys[15 - round]);
		left = temp;
	}

	std::bitset<64> combined((static_cast<uint64_t>(right.to_ullong()) << 32) | left.to_ullong());
	std::bitset<64> plaintext;

	for (int i = 0; i < 64; i++) {
		plaintext[63 - i] = combined[64 - FP[i]];
	}

	return plaintext;
}