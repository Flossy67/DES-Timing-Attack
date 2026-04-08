#include "HypothesisTest.h"
#include "DESTable.h"
#include "DataCollection.h"

#include <algorithm>
#include <cstdio>
#include <bitset>
#include <string>
#include <vector>
#include <cstdint>
#include <utility>

static std::bitset<64> applyIP(uint64_t plaintext) {
    static const uint8_t IP[64] = {
        58,50,42,34,26,18,10,2,
        60,52,44,36,28,20,12,4,
        62,54,46,38,30,22,14,6,
        64,56,48,40,32,24,16,8,
        57,49,41,33,25,17, 9,1,
        59,51,43,35,27,19,11,3,
        61,53,45,37,29,21,13,5,
        63,55,47,39,31,23,15,7
    };

    std::bitset<64> input(plaintext);
    std::bitset<64> block;
    for (int i = 0; i < 64; i++) {
        block[63 - i] = input[64 - IP[i]];
    }
    return block;
}

static std::bitset<32> getRightHalf(const std::bitset<64>& block) {
    std::bitset<32> R;
    for (int i = 0; i < 32; i++) {
        R[i] = block[i];
    }
    return R;
}

static std::bitset<48> expandHalf(const std::bitset<32>& R) {
    static const uint8_t E[48] = {
        32, 1, 2, 3, 4, 5,
         4, 5, 6, 7, 8, 9,
         8, 9,10,11,12,13,
        12,13,14,15,16,17,
        16,17,18,19,20,21,
        20,21,22,23,24,25,
        24,25,26,27,28,29,
        28,29,30,31,32, 1
    };

    std::bitset<48> expanded;
    for (int i = 0; i < 48; i++) {
        expanded[47 - i] = R[32 - E[i]];
    }
    return expanded;
}

static uint8_t getSboxInput(const std::bitset<48>& expanded, int s) {
    uint8_t val = 0;
    int base = 47 - 6 * s;
    for (int i = 0; i < 6; i++) {
        val = (val << 1) | (expanded[base - i] ? 1 : 0);
    }
    return val;
}

static uint8_t sboxLookup(int sbox, uint8_t input6) {
    uint8_t row = ((input6 >> 5) & 1) << 1 | (input6 & 1);
    uint8_t col = (input6 >> 1) & 0x0F;
    return DES::SBoxes[sbox][row][col];
}

static double computeFStat(const std::vector<uint8_t>& sboxInputs, const std::vector<double>& timings, size_t start, size_t end, int targetSbox,uint8_t k) {
    size_t N = end - start;
    if (N < 32) return 0.0;

    double grandMean = 0.0;
    for (size_t i = start; i < end; i++) {
        grandMean += timings[i];
    }
    grandMean /= N;

    double groupSum[16] = {};
    double groupSumSq[16] = {};
    size_t groupCount[16] = {};

    for (size_t i = start; i < end; i++) {
        uint8_t sboxOut = sboxLookup(targetSbox, sboxInputs[i] ^ k);
        groupSum[sboxOut] += timings[i];
        groupSumSq[sboxOut] += timings[i] * timings[i];
        groupCount[sboxOut]++;
    }

    double SSB = 0.0;
    double SSW = 0.0;
    int nGroups = 0;

    for (int g = 0; g < 16; g++) {
        if (groupCount[g] < 2) continue;
        nGroups++;
        double gMean = groupSum[g] / groupCount[g];
        double d = gMean - grandMean;
        SSB += groupCount[g] * d * d;
        SSW += groupSumSq[g] - groupCount[g] * gMean * gMean;
    }

    if (nGroups > 1 && SSW > 0.0) {
        double MSB = SSB / (nGroups - 1);
        double MSW = SSW / (N - nGroups);
        return MSB / MSW;
    }
    return 0.0;
}

static constexpr int NUM_CHUNKS = 5;
static constexpr int TOP_K_THRESHOLD = 10;

std::vector<SubkeyResult> attackSbox(const std::vector<Sample>& samples, int targetSbox) {
    size_t N = samples.size();

    std::vector<uint8_t> sboxInputs(N);
    std::vector<double> timings(N);

    for (size_t i = 0; i < N; i++) {
        std::bitset<64> permuted = applyIP(samples[i].plaintext);
        std::bitset<32> R0 = getRightHalf(permuted);
        std::bitset<48> expanded = expandHalf(R0);
        sboxInputs[i] = getSboxInput(expanded, targetSbox);
        timings[i] = static_cast<double>(samples[i].cycles);
    }

    // 1. F-stat for each candidate
    double fullF[64];
    for (uint8_t k = 0; k < 64; k++) {
        fullF[k] = computeFStat(sboxInputs, timings, 0, N, targetSbox, k);
    }

    // 2. Chunk consistency
    int topKCount[64] = {};
    size_t chunkSize = N / NUM_CHUNKS;

    for (int c = 0; c < NUM_CHUNKS; c++) {
        size_t start = c * chunkSize;
        size_t end = (c == NUM_CHUNKS - 1) ? N : start + chunkSize;

        // Compute F-stat for each candidate for chunk
        std::vector<std::pair<double, int>> ranked(64);
        for (uint8_t k = 0; k < 64; k++) {
            double f = computeFStat(sboxInputs, timings, start, end, targetSbox, k);
            ranked[k] = { f, k };
        }

        std::sort(ranked.begin(), ranked.end(),
            [](const auto& a, const auto& b) { return a.first > b.first; });

        for (int r = 0; r < TOP_K_THRESHOLD; r++) {
            topKCount[ranked[r].second]++;
        }
    }

    std::vector<SubkeyResult> results;
    results.reserve(64);

    for (uint8_t k = 0; k < 64; k++) {
        double consistency = static_cast<double>(topKCount[k]) / NUM_CHUNKS;
        double combined = fullF[k] * (0.5 + 0.5 * consistency);

        results.push_back({ k, combined, fullF[k], static_cast<uint8_t>(topKCount[k]) });
    }

    // Sort by combined score descending
    std::sort(results.begin(), results.end(),
        [](const SubkeyResult& a, const SubkeyResult& b) {
            return a.meanDiff > b.meanDiff;
        });

    return results;
}

void printResults(const std::vector<SubkeyResult>& results, size_t topK) {
    std::printf("%-12s %-14s %-14s %s\n",
        "Candidate", "Combined", "Full F-stat", "Consistency");
    std::printf("%s\n", std::string(56, '-').c_str());

    size_t limit = std::min(topK, results.size());
    for (size_t i = 0; i < limit; i++)
    {
        const auto& r = results[i];
        std::printf("0x%02X (%-2u)    %-14.4f %-14.4f %d/%d\n",
            r.candidate, r.candidate,
            r.meanDiff, r.tStat,
            r.coldLine, NUM_CHUNKS);
    }
}