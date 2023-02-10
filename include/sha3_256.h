#ifndef KECCAK_SHA3_256_H
#define KECCAK_SHA3_256_H

#include <cassert>

#include "sha3.h"

namespace keccak {

class SHA3_256 : public SHA3<256> {
public:
    explicit SHA3_256(uint8_t flag = 0);
};

} // namespace keccak

#endif //KECCAK_SHA3_256_H