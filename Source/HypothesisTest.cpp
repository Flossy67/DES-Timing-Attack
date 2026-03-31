#include "HypothesisTest.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <bitset>
#include <string>


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


static double mean(const std::vector<uint64_t>& v) {
    if (v.empty()) return 0.0;
    double sum = 0.0;
    for (auto x : v) sum += static_cast<double>(x);
    return sum / static_cast<double>(v.size());
}

// Welch's t-statistic — does not assume equal variance
static double welchT(const std::vector<uint64_t>& a, const std::vector<uint64_t>& b) {
    if (a.size() < 2 || b.size() < 2) {
        return 0.0;
    }

    auto variance = [](const std::vector<uint64_t>& v, double m) {
        double var = 0.0;
        for (auto x : v) {
            double d = static_cast<double>(x) - m; var += d * d; 
        }
        return var / static_cast<double>(v.size() - 1);
        };

    double ma = mean(a), mb = mean(b);
    double va = variance(a, ma), vb = variance(b, mb);
    double denom = std::sqrt(va / a.size() + vb / b.size());
    if (denom == 0.0) {
        return 0.0;
    }
    return (mb - ma) / denom;
}

std::vector<SubkeyResult> attackSbox1(const std::vector<Sample>& samples) {
    std::vector<SubkeyResult> results;
    results.reserve(64);

    for (uint8_t k = 0; k < 64; k++) {
        std::vector<uint64_t> buckets[64];
        for (auto& b : buckets) {
            b.reserve(samples.size() / 64);
        }

        for (const auto& s : samples) {
            std::bitset<64> permuted = applyIP(s.plaintext);
            std::bitset<32> R0 = getRightHalf(permuted);
            std::bitset<48> expanded = expandHalf(R0);
            uint8_t input6 = getSboxInput(expanded, 0) ^ k;
            buckets[input6].push_back(s.cycles);
        }

        double bucketMeans[64] = {};
        int filled = 0;
        double grandSum = 0.0;

        for (int b = 0; b < 64; b++) {
            if (buckets[b].empty()) {
                continue;
            }
            bucketMeans[b] = mean(buckets[b]);
            grandSum += bucketMeans[b];
            filled++;
        }

        if (filled < 2) { 
            results.push_back({ k, 0.0, 0.0, 0 }); 
            continue; 
        }

        double grandMean = grandSum / filled;
        double var = 0.0;
        for (int b = 0; b < 64; b++) {
            if (buckets[b].empty()) {
                continue;
            }
            double d = bucketMeans[b] - grandMean;
            var += d * d;
        }
        var /= (filled - 1);


        double minMean = 1e18, maxMean = -1e18;
        int    minBucket = 0, maxBucket = 0;
        for (int b = 0; b < 64; ++b) {
            if (buckets[b].empty()) {
                continue;
            }
            if (bucketMeans[b] < minMean) {
                minMean = bucketMeans[b]; minBucket = b; 
            }
            if (bucketMeans[b] > maxMean) {
                maxMean = bucketMeans[b]; maxBucket = b; 
            }
        }
        double tStat = (maxBucket != minBucket) ? std::abs(welchT(buckets[minBucket], buckets[maxBucket])): 0.0;

        results.push_back({ k, var, tStat, static_cast<uint8_t>(maxBucket) });
    }

    std::sort(results.begin(), results.end(), 
        [](const SubkeyResult& a, const SubkeyResult& b) {
            return a.meanDiff > b.meanDiff;
        });

    return results;
}

void printResults(const std::vector<SubkeyResult>& results, size_t topK) {
    std::printf("%-12s %-16s %-12s %-10s\n",
        "Candidate", "BucketVarScore", "t-stat", "MaxMissBucket");
    std::printf("%s\n", std::string(54, '-').c_str());

    size_t limit = std::min(topK, results.size());
    for (size_t i = 0; i < limit; i++)
    {
        const auto& r = results[i];
        std::printf("0x%02X (%-2u)    %-16.4f %-12.4f %u\n",
            r.candidate, r.candidate,
            r.meanDiff, r.tStat, r.coldLine);
    }
}