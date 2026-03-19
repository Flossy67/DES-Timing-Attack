#pragma once
#include "KeyExpansion.h"
#include "DESEncryption.h"
#include "DESTable.h"

namespace DES {
	std::bitset<64> decrypt(const std::bitset<64>& ciphertext, const std::bitset<48> subkeys[16]);
}
