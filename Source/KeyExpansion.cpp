#include "KeyExpansion.h"

void DES::keyExpansion(std::bitset<48> subkeys[16], const std::bitset<64>& key) {
	std::bitset<56> cd = permutedChoice1(key);

	for (int round = 0; round < 16; round++) {
		cd = leftShift(cd, round);
		subkeys[round] = permutedChoice2(cd);
	}
}

std::bitset<56> DES::permutedChoice1(const std::bitset<64>& key)
{
	std::bitset<56> cd;
	for (int i = 0; i < 56; i++) {
		cd[55 - i] = key[64 - PC1[i]];
	}
	return cd;
}

std::bitset<48> DES::permutedChoice2(const std::bitset<56>& cd)
{
	std::bitset<48> subkey;
	for (int i = 0; i < 48; i++) {
		subkey[47 - i] = cd[56 - PC2[i]];
	}
	return subkey;
}

std::bitset<56> DES::leftShift(const std::bitset<56>& cd, int round)
{
	int shift = SHIFT_SCHEDULE[round];
	uint64_t c = (cd >> 28).to_ullong() & 0x0FFFFFFF;
	uint64_t d = cd.to_ullong() & 0x0FFFFFFF;

	c = ((c << shift) | (c >> (28 - shift))) & 0x0FFFFFFF;
	d = ((d << shift) | (d >> (28 - shift))) & 0x0FFFFFFF;
	return std::bitset<56>((c << 28) | d);
}
