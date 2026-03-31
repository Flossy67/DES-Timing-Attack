#include "Timing.h"
#include "DESTable.h"
#include <cstdint>

const uint8_t* g_sboxBase = reinterpret_cast<const uint8_t*>(DES::PaddedSBoxes);