#include "DataCollection.h"
#include "HypothesisTest.h"
#include "KeyExpansion.h"
#include "DESEncryption.h"
#include "DESTable.h"
#include "Timing.h"

#include <bitset>
#include <cstdio>
#include <vector>

void probeCacheMissPenalty() {
    constexpr uint64_t KEY = 0x133457799BBCDFF1ULL;
    constexpr int      REPS = 10000;

    std::bitset<48> subkeys[16];
    DES::keyExpansion(subkeys, std::bitset<64>(KEY));

    std::bitset<64> pt(0xA8EB4DEA48C3711BULL);

    std::vector<uint64_t> coldTimes, warmTimes;
    coldTimes.reserve(REPS);
    warmTimes.reserve(REPS);

    volatile uint64_t sink = 0;

    // Cold: flush before every encrypt
    for (int i = 0; i < REPS; i++) {
        flushSboxCache();
        uint64_t t0 = rdtsc_start();
        auto ct = DES::encrypt(pt, subkeys);
        uint64_t t1 = rdtsc_end();
        sink ^= ct.to_ullong();
        coldTimes.push_back(t1 - t0);
    }

    // Warm: no flush, S-boxes stay in cache
    for (int i = 0; i < REPS; i++) {
        uint64_t t0 = rdtsc_start();
        auto ct = DES::encrypt(pt, subkeys);
        uint64_t t1 = rdtsc_end();
        sink ^= ct.to_ullong();
        warmTimes.push_back(t1 - t0);
    }

    (void)sink;

    auto mean = [](const std::vector<uint64_t>& v) {
        double s = 0; 
        for (auto x : v) {
            s += x;
        }
        return s / v.size();
        };

    std::printf("Cold mean: %.2f cycles\n", mean(coldTimes));
    std::printf("Warm mean: %.2f cycles\n", mean(warmTimes));
    std::printf("Difference: %.2f cycles\n", mean(coldTimes) - mean(warmTimes));
}

int main() {
    DES::initPaddedSBoxes();

    constexpr uint64_t KEY = 0x133457799BBCDFF1ULL;
    constexpr uint64_t SEED = 0xDEADBEEFDEADBEEFULL;

    auto samples = collectSamples(KEY, SEED, 200'000, 2'000, false);

    std::printf("\nDebug: predicted S-box 1 inputs for k=0\n");
    for (size_t i = 0; i < 10 && i < samples.size(); i++) {
        std::bitset<64> input(samples[i].plaintext);
        std::bitset<64> permuted;

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

        for (int j = 0; j < 64; j++) {
            permuted[63 - j] = input[64 - IP[j]];
        }

        std::bitset<32> R0;
        for (int j = 0; j < 32; j++) {
            R0[j] = permuted[j];
        }

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
        for (int j = 0; j < 48; j++) {
            expanded[47 - j] = R0[32 - E[j]];
        }
            

        uint8_t input6 = 0;
        for (int j = 0; j < 6; j++) {
            input6 = (input6 << 1) | (expanded[47 - j] ? 1 : 0);
        }
            
        std::printf("Plaintext: %016llX  input6: %02X  line: %d\n",
            static_cast<unsigned long long>(samples[i].plaintext),
            input6, input6 / 16);
    }


    std::bitset<48> subkeys[16];
    DES::keyExpansion(subkeys, std::bitset<64>(KEY));

    uint8_t actualK = 0;
    for (int i = 0; i < 6; i++) {
        actualK = (actualK << 1) | (subkeys[0][47 - i] ? 1 : 0);
    }
        

    std::printf("Actual K1 S-box 1 bits: 0x%02X (%u)\n", actualK, actualK);

    uint8_t trueK = actualK;
    int lineCounts[4] = {};
    double lineMeans[4] = {};
    std::vector<uint64_t> lineVecs[4];

    for (const auto& s : samples) {
        std::bitset<64> input(s.plaintext);
        std::bitset<64> permuted;
        static const uint8_t IP[64] = {
            58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,
            62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
            57,49,41,33,25,17, 9,1,59,51,43,35,27,19,11,3,
            61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7
        };

        for (int j = 0; j < 64; j++) {
            permuted[63 - j] = input[64 - IP[j]];
        }
            

        std::bitset<32> R0;
        for (int j = 0; j < 32; j++) {
            R0[j] = permuted[j];
        }

        static const uint8_t E[48] = {
            32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
             8, 9,10,11,12,13, 12,13,14,15,16,17,
            16,17,18,19,20,21, 20,21,22,23,24,25,
            24,25,26,27,28,29, 28,29,30,31,32, 1
        };

        std::bitset<48> expanded;
        for (int j = 0; j < 48; j++) {
            expanded[47 - j] = R0[32 - E[j]];
        }
            

        uint8_t input6 = 0;
        for (int j = 0; j < 6; j++) {
            input6 = (input6 << 1) | (expanded[47 - j] ? 1 : 0);
        }
            
        input6 ^= trueK;
        int line = input6 / 16;
        lineVecs[line].push_back(s.cycles);
    }

    std::printf("\nLine distribution for true key 0x%02X:\n", trueK);
    for (int l = 0; l < 4; l++) {
        double m = 0;
        for (auto c : lineVecs[l]) m += c;
        m /= lineVecs[l].size();
        std::printf("  Line %d: n=%-6zu mean=%.2f\n", l, lineVecs[l].size(), m);
    }

    probeCacheMissPenalty();

    writeCsv("samples.csv", samples);

    auto results = attackSbox1(samples);
    printResults(results, 10);
    return 0;
}