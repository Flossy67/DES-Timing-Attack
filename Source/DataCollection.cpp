#include "DataCollection.h"
#include "Timing.h"
#include "DESEncryption.h"
#include "KeyExpansion.h"
#include "DESTable.h"

#include <random>
#include <fstream>
#include <cstdio>
#include <bitset>
#include <stdexcept>
#include <algorithm>
#include <vector>
#include <cstdint>
#include <string>

static void rejectOutliers(std::vector<Sample>& samples) {
    std::vector<uint64_t> vals;
    vals.reserve(samples.size());

    for (const auto& s : samples) {
        vals.push_back(s.cycles);
    }

    auto mid = vals.begin() + vals.size() / 2;
    std::nth_element(vals.begin(), mid, vals.end());
    uint64_t med = *mid;

    std::vector<uint64_t> devs;
    devs.reserve(vals.size());
    for (auto c : vals) {
        devs.push_back(c > med ? c - med : med - c);
    }

    auto madMid = devs.begin() + devs.size() / 2;
    std::nth_element(devs.begin(), madMid, devs.end());
	uint64_t mad = *madMid;

    uint64_t low = (med > 3 * mad) ? med - 3 * mad : 0;
    uint64_t high = med + 3 * mad;

    samples.erase(
        std::remove_if(samples.begin(), samples.end(),
            [low, high](const Sample& s) { return s.cycles < low || s.cycles > high; }),
        samples.end());
}
std::vector<Sample> collectSamples(uint64_t key, uint64_t seed, size_t n, size_t warmupRounds, bool flushBetween)
{
    pinThreadToCore(0); 

    std::bitset<64> keyBits(key);
    std::bitset<48> subkeys[16];
	DES::keyExpansion(subkeys, key);

    std::mt19937_64 rng(seed);
    std::vector<uint64_t> plaintexts(n);
    for (size_t i = 0; i < n; i++) {
        plaintexts[i] = rng();
	}

    std::vector<std::bitset<64>> ptBits(n);
    for (size_t i = 0; i < n; i++) {
        ptBits[i] = std::bitset<64>(plaintexts[i]);
    }

    volatile uint64_t sink = 0; 
    for (size_t i = 0; i < warmupRounds; i++) {
        sink ^= DES::encrypt(plaintexts[i % n], subkeys).to_ullong();
    }

    std::vector<Sample> samples;
    samples.reserve(n);

    for (size_t i = 0; i < n; i++) {
        if (flushBetween) {
            flushSboxCache();
        }

        std::bitset<64> block;
        for (int j = 0; j < 64; j++) {
            block[63 - j] = ptBits[i][64 - DES::IP[j]];
        }
        std::bitset<32> R0(block.to_ullong() & 0xFFFFFFFF);
        std::bitset<48> expanded = DES::expand(R0) ^ subkeys[0];

        uint64_t t0 = rdtsc_start();
        auto result = DES::substituePadded(expanded);
        uint64_t t1 = rdtsc_end();

        sink ^= result.to_ullong();
        samples.push_back({ plaintexts[i], t1 - t0 });
    }

    (void)sink;

    rejectOutliers(samples);

    std::printf("Collected %zu samples \n", samples.size());
    return samples;
}

bool writeCsv(const std::string& path, const std::vector<Sample>& samples)
{
    std::ofstream f(path, std::ios::binary);
    if (!f) {
        throw std::runtime_error("Failed to open file for writing: " + path);
        return false;
    }
    f << "plaintext_hex,cycles\n";
    char buf[48];
    for (const auto& s : samples)
    {
        std::snprintf(buf, sizeof(buf), "%016llX,%llu\n",
            static_cast<unsigned long long>(s.plaintext),
            static_cast<unsigned long long>(s.cycles));
        f << buf;
    }
    return f.good();
}
