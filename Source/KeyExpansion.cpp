#include "KeyExpansion.h"
/*
	1. Apply PC-1 to the 64-bit key to get a 56-bit key (CD).
	2. For each of the 16 rounds:
	   a. Left shift CD according to the shift schedule.
	   b. Apply PC-2 to CD to get the 48-bit subkey for that round.
*/

// Generate 16 subkeys from the original 64-bit key
void DES::keyExpansion(std::bitset<48> subkeys[16], const std::bitset<64>& key) {
	std::bitset<56> cd = permutedChoice1(key);

	for (int round = 0; round < 16; round++) {
		cd = leftShift(cd, round);
		subkeys[round] = permutedChoice2(cd);
	}
}

// Reduce 64-bit key to 56 bits using PC-1
std::bitset<56> DES::permutedChoice1(const std::bitset<64>& key)
{
	std::bitset<56> cd;
	// Bitsets are indexed from right to left
	for (int i = 0; i < 56; i++) {
		cd[55 - i] = key[64 - PC1[i]];
	}
	return cd;
}
// Reduce 56-bit CD to 48 bits using PC-2
std::bitset<48> DES::permutedChoice2(const std::bitset<56>& cd)
{
	std::bitset<48> subkey;
	// Bitsets are indexed from right to left
	for (int i = 0; i < 48; i++) {
		subkey[47 - i] = cd[56 - PC2[i]];
	}
	return subkey;
}

std::bitset<56> DES::leftShift(const std::bitset<56>& cd, int round)
{
	int shift = SHIFT_SCHEDULE[round];
	// Split CD into C and D, ullong is used for easier bit manipulation
	uint64_t c = (cd >> 28).to_ullong() & 0x0FFFFFFF;
	uint64_t d = cd.to_ullong() & 0x0FFFFFFF;

	// Left shift each half, masking 28 bits
	c = ((c << shift) | (c >> (28 - shift))) & 0x0FFFFFFF;
	d = ((d << shift) | (d >> (28 - shift))) & 0x0FFFFFFF;

	// Combine C and D back into a 56-bit CD
	return std::bitset<56>((c << 28) | d);
}
