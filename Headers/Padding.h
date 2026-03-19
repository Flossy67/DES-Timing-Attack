#pragma once
#include <vector>
#include <cstdint>

namespace Padding {
	static constexpr size_t BLOCK_SIZE = 8;
	void pkcs7Pad(std::vector<uint8_t>& data);
	void pkcs7Unpad(std::vector<uint8_t>& data);
}