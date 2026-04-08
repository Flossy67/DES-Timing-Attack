#include "DataCollection.h"
#include "HypothesisTest.h"
#include "KeyExpansion.h"
#include "DESTable.h"

#include <bitset>
#include <cstdio>
#include <vector>
#include <cstdint>


// Extract the 6-bit subkey feeding S-box from round-1 subkey
static uint8_t extractSboxKey(const std::bitset<48>& subkey, int sbox) {
    uint8_t val = 0;
    int base = 47 - 6 * sbox;
    for (int i = 0; i < 6; i++) {
        val = (val << 1) | (subkey[base - i] ? 1 : 0);
    }
    return val;
}


int main() {
    DES::initPaddedSBoxes();

    constexpr uint64_t KEY = 0x133457799BBCDFF1ULL;
    constexpr uint64_t SEED = 0xDEADBEEFDEADBEEFULL;

    auto samples = collectSamples(KEY, SEED, 1'000'000, 2'000, true);

    std::bitset<48> subkeys[16];
    DES::keyExpansion(subkeys, std::bitset<64>(KEY));

    // Print actual subkey bits for all 8 S-boxes
    uint8_t actualKeys[8];
    std::printf("\nActual round-1 subkey bits per S-box:\n");
    for (int s = 0; s < 8; s++) {
        actualKeys[s] = extractSboxKey(subkeys[0], s);
        std::printf("  S-box %d (S%d): 0x%02X (%u)\n", s, s + 1, actualKeys[s], actualKeys[s]);
    }

    writeCsv("samples.csv", samples);

    // Attack all 8 S-boxes and report rank of correct key
    std::printf("\n========================================\n");
    std::printf("        ATTACK RESULTS SUMMARY\n");
    std::printf("========================================\n");

    for (int s = 0; s < 8; s++) {
        std::printf("\n=== S-box %d | True key: 0x%02X (%u) ===\n",
            s + 1, actualKeys[s], actualKeys[s]);

        auto results = attackSbox(samples, s);
        printResults(results, 15);

        // Find rank of correct key
        for (size_t i = 0; i < results.size(); i++) {
            if (results[i].candidate == actualKeys[s]) {
                std::printf(">>> Correct key 0x%02X ranked #%zu out of 64 <<<\n",
                    actualKeys[s], i + 1);
                break;
            }
        }
    }

    return 0;
}