#pragma once
#include <cstdint>
#include <vector>
#include <string>

struct Sample {
	uint64_t plaintext;
	uint64_t cycles;
};

std::vector<Sample> collectSamples(uint64_t key, uint64_t seed, size_t n, size_t warmupRounds, bool flushBetween);
bool writeCsv(const std::string& path, const std::vector<Sample>& samples);
