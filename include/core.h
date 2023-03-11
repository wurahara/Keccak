#ifndef KECCAK_CORE_H
#define KECCAK_CORE_H

#include <array>
#include <cstdint>

namespace keccak::util {

constexpr size_t P_LEN = 25;

constexpr uint64_t USE_KECCAK_FLAG = 0x80000000;

constexpr inline uint64_t cw(uint64_t x) {
    return (x) & (~USE_KECCAK_FLAG);
}

constexpr inline uint64_t rotl_64(uint64_t x, uint64_t y) {
    return x << y | x >> (sizeof(uint64_t) * 8 - y);
}

constexpr uint64_t round_constants[24] = {
        0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
        0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
        0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
        0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
        0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
        0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
};

constexpr uint32_t rotate_constants[24] = {
        1, 3, 6, 10, 15, 21, 28, 36,
        45, 55, 2, 14, 27, 41, 56, 8,
        25, 43, 62, 18, 39, 61, 20, 44,
};

constexpr uint32_t pi[24] = {
        10, 7, 11, 17, 18, 3, 5, 16,
        8, 21, 24, 4, 15, 23, 19, 13,
        12, 2, 20, 14, 22, 9, 6, 1,
};

constexpr inline void keccak_f(std::array<uint64_t, util::P_LEN> &state) {
    uint64_t temp, bc[5];

    for (uint64_t round: round_constants) {
        // Theta
        for (int i = 0; i < 5; ++i) bc[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];
        for (int i = 0; i < 5; ++i) {
            temp = bc[(i + 4) % 5] ^ rotl_64(bc[(i + 1) % 5], 1);
            for (int j = 0; j < 25; j += 5) state[j + i] ^= temp;
        }

        // Rho and Pi
        temp = state[1];
        for (int i = 0; i < 24; ++i) {
            uint32_t r = pi[i];
            bc[0] = state[r];
            state[r] = rotl_64(temp, rotate_constants[i]);
            temp = bc[0];
        }

        // Chi
        for (int j = 0; j < 25; j += 5) {
            for (int i = 0; i < 5; i++)
                bc[i] = state[j + i];
            for (int i = 0; i < 5; i++)
                state[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }

        // Iota
        state[0] ^= round;
    }
}

} // namespace keccak::util

#endif //KECCAK_CORE_H
