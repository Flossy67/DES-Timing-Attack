#include "DESEncryption.h"
// Encrypts a 64-bit plaintext block using the DES algorithm and a 64-bit key
std::bitset<64> DES::encrypt(const std::bitset<64>& plaintext, const std::bitset<48> subkeys[16])
{
	// Initial Permutation
	std::bitset<64> block;
	for (int i = 0; i < 64; i++) {
		block[63 - i] = plaintext[64 - IP[i]];
	}
	// Split into left and right halves
	std::bitset<32> left = block.to_ullong() >> 32;
	std::bitset<32> right = block.to_ullong() & 0xFFFFFFFF;
	
	// 16 rounds of DES
	// Each round: new R = L XOR f(R, subkey), new L = old R
	for (int round = 0; round < 16; round++) {
		std::bitset<32> temp = right;
		right = left ^ fFunction(right, subkeys[round]);
		left = temp;
	}
	
	// Combine halves R + L
	std::bitset<64> combined((static_cast<uint64_t>(right.to_ullong()) << 32) | left.to_ullong());
	std::bitset<64> ciphertext;
	
	// Final Permutation
	for (int i = 0; i < 64; i++) {
		ciphertext[63 - i] = combined[64 - FP[i]];
	}
	return ciphertext;
}

// Expands a 32-bit half-block to 48-bits using the E table
std::bitset<48> DES::expand(const std::bitset<32>& half_block)
{
	std::bitset<48> expanded;
	// Bitsets are indexed right to left
	for (int i = 0; i < 48; i++) {
		expanded[47 - i] = half_block[32 - E[i]];
	}
	return expanded;
}

// Applied Feistel F Function: F(R, K) = P(S(E(R) XOR K))
std::bitset<32> DES::fFunction(const std::bitset<32>& half_block, const std::bitset<48>& round_key)
{
	std::bitset<48> expanded = expand(half_block) ^ round_key;
	std::bitset<32> substituted = substitute(expanded);
	std::bitset<32> permuted = permute(substituted);
	return permuted;
}

// Substitute 48-bit input to 32-bit output using the 8 S-boxes
// Each S-box takes 6 bits and produces 4 bits
std::bitset<32> DES::substitute(const std::bitset<48>& expanded)
{
	uint64_t input = expanded.to_ullong();
	uint64_t output = 0;

	for (int i = 0; i < 8; i++) {
		uint8_t shift = 48 - 6 * (i + 1);
		// Extract 6 bits for the current S-box
		std::bitset<6> six_bits((input >> shift) & 0x3F);

		// First and last bit determines the row
		uint8_t row = six_bits[5] << 1 | six_bits[0];

		// Middle 4 bits determine the column
		uint8_t col = six_bits[4] << 3 | six_bits[3] << 2 | six_bits[2] << 1 | six_bits[1];

		output |= static_cast<uint32_t>(SBoxes[i][row][col]) << (32 - 4 * (i + 1));
	}
	return std::bitset<32>(output);
}

// Applies P permutation to the 32-bit input from the S-boxes
std::bitset<32> DES::permute(const std::bitset<32>& input)
{
	std::bitset<32> permuted;
	// Bitsets are indexed right to left
	for (int i = 0; i < 32; i++) {
		permuted[31 - i] = input[32 - P[i]];
	}
	return permuted;
}
