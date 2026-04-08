#include "Padding.h"

#include <vector>
#include <cstdint>
#include <stdexcept>

void Padding::pkcs7Pad(std::vector<uint8_t>& data) {
	// Calculate padding length
	uint8_t pad_len = static_cast<uint8_t>(BLOCK_SIZE - (data.size() % BLOCK_SIZE));

	// If data is already a multiple of BLOCK_SIZE, add a full block of padding
	data.insert(data.end(), pad_len, pad_len);
}

void Padding::pkcs7Unpad(std::vector<uint8_t>& data) {
	if (data.empty()) {
		throw std::runtime_error("Invalid padding: bad data length");
	}

	uint8_t pad_len = data.back();

	if (pad_len == 0 || pad_len > BLOCK_SIZE) {
		throw std::runtime_error("Invalid padding: bad padding length");
	}

	for (size_t i = data.size() - pad_len; i < data.size(); i++) {
		if (data[i] != pad_len) {
			throw std::runtime_error("Invalid padding: incorrect padding bytes");
		}
	}

	data.resize(data.size() - pad_len);
}
