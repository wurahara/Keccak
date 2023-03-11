#ifndef KECCAK_SHA3_H
#define KECCAK_SHA3_H

#include <array>
#include <cassert>
#include <cstdint>

#include "core.h"

namespace keccak {

template<size_t BIT> requires (BIT == 256 || BIT == 384 || BIT == 512)
class SHA3 {
public:
    static constexpr size_t SPONGE_WORDS = 1600 / 8 / sizeof(uint64_t);

private:
    uint64_t saved;
    uint32_t byte_index;
    uint32_t word_index;
    uint32_t capacity_words;
    std::array<uint64_t, SHA3::SPONGE_WORDS> state;

public:
    constexpr explicit SHA3(uint8_t flag = 0);
    constexpr void update(const void *buf_in, size_t length);
    constexpr std::array<uint64_t, SHA3::SPONGE_WORDS> finalize();

public:
    constexpr static std::array<uint64_t, SHA3::SPONGE_WORDS> hash_buffer(const void *buf_in, uint32_t length, int flag);
};

template<size_t BIT>
requires (BIT == 256 || BIT == 384 || BIT == 512)
constexpr SHA3<BIT>::SHA3(uint8_t flag)
        : saved{0}, byte_index{0}, word_index{0}, capacity_words{2 * BIT / (8 * sizeof(uint64_t))}, state{} {
    this->capacity_words |= (flag == 1 ? util::USE_KECCAK_FLAG : 0);
}

template<size_t BIT>
requires (BIT == 256 || BIT == 384 || BIT == 512)
constexpr void SHA3<BIT>::update(const void *buf_in, size_t length) {
    uint32_t old_tail = (8 - this->byte_index) & 7;

    size_t words;
    uint32_t tail;

    const auto *buffer = static_cast<const uint8_t *>(buf_in);

    assert(this->byte_index < 8);
    assert(this->word_index < SHA3::SPONGE_WORDS);

    if (length < old_tail) {
        while (length--) this->saved |= static_cast<uint64_t>(*buffer++) << ((this->byte_index++) * 8);
        assert(this->byte_index < 8);
        return;
    }

    if (old_tail) {
        length -= old_tail;
        while (old_tail--) this->saved |= static_cast<uint64_t>(*buffer++) << ((this->byte_index++) * 8);
        this->state[this->word_index] ^= this->saved;
        assert(this->byte_index == 8);
        this->byte_index = 0;
        this->saved = 0;
        if (++this->word_index == (SHA3::SPONGE_WORDS - util::cw(this->capacity_words))) {
            util::keccak_f(this->state);
            this->word_index = 0;
        }
    }
    assert(this->byte_index == 0);

    words = length / sizeof(uint64_t);
    tail = length - words * sizeof(uint64_t);

    for (int i = 0; i < words; ++i, buffer += sizeof(uint64_t)) {
        const uint64_t t =
                (uint64_t) (buffer[0]) |
                ((uint64_t) (buffer[1]) << 8 * 1) | ((uint64_t) (buffer[2]) << 8 * 2) |
                ((uint64_t) (buffer[3]) << 8 * 3) | ((uint64_t) (buffer[4]) << 8 * 4) |
                ((uint64_t) (buffer[5]) << 8 * 5) | ((uint64_t) (buffer[6]) << 8 * 6) |
                ((uint64_t) (buffer[7]) << 8 * 7);

        this->state[this->word_index] ^= t;
        if (++this->word_index == (SHA3::SPONGE_WORDS - util::cw(this->capacity_words))) {
            util::keccak_f(this->state);
            this->word_index = 0;
        }
    }

    assert(this->byte_index == 0 && tail < 8);
    while (tail--) {
        this->saved |= static_cast<uint64_t>(*buffer++) << ((this->byte_index++) * 8);
    }
    assert(this->byte_index < 8);
}

template<size_t BIT>
requires (BIT == 256 || BIT == 384 || BIT == 512)
constexpr std::array<uint64_t, SHA3<BIT>::SPONGE_WORDS> SHA3<BIT>::finalize() {
    uint64_t t;
    if (this->capacity_words & util::USE_KECCAK_FLAG) {
        t = static_cast<uint64_t>((static_cast<uint64_t>(1) << (this->byte_index * 8)));
    } else {
        t = static_cast<uint64_t>((static_cast<uint64_t>((0x02 | 1 << 2)) << (this->byte_index * 8)));
    }
    this->state[this->word_index] ^= this->saved ^ t;
    this->state[SHA3::SPONGE_WORDS - util::cw(this->capacity_words) - 1] ^= 0x8000000000000000ULL;
    util::keccak_f(this->state);
    return this->state;
}

template<size_t BIT>
requires (BIT == 256 || BIT == 384 || BIT == 512)
std::array<uint64_t, SHA3<BIT>::SPONGE_WORDS>
constexpr SHA3<BIT>::hash_buffer(const void *buf_in, uint32_t length, int flag) {
    SHA3<BIT> sha3(flag);
    sha3.update(buf_in, length);
    return sha3.finalize();
}

} // namespace keccak

#endif //KECCAK_SHA3_H