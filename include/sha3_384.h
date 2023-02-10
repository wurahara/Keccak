#ifndef KECCAK_SHA3_384_H
#define KECCAK_SHA3_384_H

#include <cassert>

#include "sha3.h"

namespace keccak {

class SHA3_384 : public SHA3<384> {
public:
    explicit SHA3_384(uint8_t flag = 0);
};

} // namespace keccak

#endif //KECCAK_SHA3_384_H