#pragma once
#include <cstdint>
#include <intrin.h>
#include <Windows.h>
#include <emmintrin.h>

// Pointer to first byte of sboxes
extern const uint8_t* g_sboxBase;
constexpr size_t SBOX_FLUSH_BYTES = 8 * 4 * 16 * 64; 


// Pin current thread to core to reduce noise in timing measurements
inline void pinThreadToCore(DWORD core = 0) {
	HANDLE hThread = GetCurrentThread();
	DWORD_PTR mask = (DWORD_PTR(1) << core);
	SetThreadAffinityMask(hThread, mask);
}

// Flush sbox cache to ensure misses 
inline void flushSboxCache() {
	for (size_t i = 0; i < SBOX_FLUSH_BYTES; i += 64) {
		_mm_clflush(g_sboxBase + i);
	}
	_mm_mfence(); // wait for all flushes to complete
}

// Read Time Stamp Counter to get accurate timing
inline uint64_t rdtsc_start() {
	unsigned int aux; 
	_mm_lfence();
	return __rdtscp(&aux);
}

inline uint64_t rdtsc_end() {
	unsigned int aux;
	uint64_t t = __rdtscp(&aux);
	_mm_lfence();
	return t;
}