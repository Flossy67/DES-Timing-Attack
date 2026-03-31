#pragma once
#include "KeyExpansion.h"
#include "DESTable.h"

namespace DES {
	std::bitset<64> encrypt(const std::bitset<64>& plaintext, const std::bitset<48> subkeys[16]);
	std::bitset<48> expand(const std::bitset<32>& half_block);
	std::bitset<32> fFunction(const std::bitset<32>& half_block, const std::bitset<48>& round_key);
	std::bitset<32> substitute(const std::bitset<48>& expanded);
	std::bitset<32> substituePadded(const std::bitset<48>& expanded);
	std::bitset<32> permute(const std::bitset<32>& input);
}