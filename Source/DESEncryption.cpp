#include "DESEncryption.h"
#include "DESTable.h"

#include <bitset>
#include <cstdint>
#include <string.h>

DES::PaddedSBoxHalf DES::PaddedSBoxHalves[8][2];

void DES::initPaddedSBoxes() {
	for (int s = 0; s < 8; s++) {
		std::memset(&PaddedSBoxHalves[s][0], 0, sizeof(PaddedSBoxHalf));
		std::memset(&PaddedSBoxHalves[s][1], 0, sizeof(PaddedSBoxHalf));
		for (int r = 0; r < 4; r++) {
			int half = r / 2;      // rows 0,1 -> half 0; rows 2,3 -> half 1
			int slot = r % 2;      // position within half
			for (int c = 0; c < 16; c++) {
				PaddedSBoxHalves[s][half].value[slot][c] = SBoxes[s][r][c];
			}
		}
	}
}

std::bitset<64> DES::encrypt(const std::bitset<64>& plaintext, const std::bitset<48> subkeys[16])
{
	std::bitset<64> block;
	for (int i = 0; i < 64; i++) {
		block[63 - i] = plaintext[64 - IP[i]];
	}

	std::bitset<32> left = block.to_ullong() >> 32;
	std::bitset<32> right = block.to_ullong() & 0xFFFFFFFF;
	
	for (int round = 0; round < 16; round++) {
		std::bitset<32> temp = right;
		right = left ^ fFunction(right, subkeys[round]);
		left = temp;
	}
	
	std::bitset<64> combined((static_cast<uint64_t>(right.to_ullong()) << 32) | left.to_ullong());
	std::bitset<64> ciphertext;

	for (int i = 0; i < 64; i++) {
		ciphertext[63 - i] = combined[64 - FP[i]];
	}
	return ciphertext;
}

std::bitset<48> DES::expand(const std::bitset<32>& half_block)
{
	std::bitset<48> expanded;
	for (int i = 0; i < 48; i++) {
		expanded[47 - i] = half_block[32 - E[i]];
	}
	return expanded;
}

std::bitset<32> DES::fFunction(const std::bitset<32>& half_block, const std::bitset<48>& round_key)
{
	std::bitset<48> expanded = expand(half_block) ^ round_key;
	std::bitset<32> substituted = substituePadded(expanded);
	std::bitset<32> permuted = permute(substituted);
	return permuted;
}

std::bitset<32> DES::substitute(const std::bitset<48>& expanded)
{
	uint64_t input = expanded.to_ullong();
	uint64_t output = 0;

	for (int i = 0; i < 8; i++) {
		uint8_t shift = 48 - 6 * (i + 1);
		std::bitset<6> six_bits((input >> shift) & 0x3F);

		uint8_t row = six_bits[5] << 1 | six_bits[0];
		uint8_t col = six_bits[4] << 3 | six_bits[3] << 2 | six_bits[2] << 1 | six_bits[1];

		output |= static_cast<uint32_t>(SBoxes[i][row][col]) << (32 - 4 * (i + 1));
	}
	return std::bitset<32>(output);
}

std::bitset<32> DES::substituePadded(const std::bitset<48>& expanded) {
	uint64_t input = expanded.to_ullong();
	uint64_t output = 0;
	for (int i = 0; i < 8; i++) {
		uint8_t shift = 48 - 6 * (i + 1);
		std::bitset<6> six_bits((input >> shift) & 0x3F);
		uint8_t row = six_bits[5] << 1 | six_bits[0];
		uint8_t col = six_bits[4] << 3 | six_bits[3] << 2 | six_bits[2] << 1 | six_bits[1];
		int half = row / 2;
		int slot = row % 2;
		output |= static_cast<uint32_t>(PaddedSBoxHalves[i][half].value[slot][col]) << (32 - 4 * (i + 1));
	}
	return std::bitset<32>(output);
}

std::bitset<32> DES::permute(const std::bitset<32>& input)
{
	std::bitset<32> permuted;
	for (int i = 0; i < 32; i++) {
		permuted[31 - i] = input[32 - P[i]];
	}
	return permuted;
}

