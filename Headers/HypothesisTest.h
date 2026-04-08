#pragma once
#include "DataCollection.h"
#include <cstdint>
#include <vector>

struct SubkeyResult {
	uint8_t candidate;
	double meanDiff;
	double tStat;
	uint8_t coldLine;
};

std::vector<SubkeyResult> attackSbox(const std::vector <Sample>& samples, int targetSbox);
void printResults(const std::vector<SubkeyResult>& results, size_t topK = 10);
