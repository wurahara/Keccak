#ifndef KECCAK_SHA3_512_H
#define KECCAK_SHA3_512_H

#include <cassert>

#include "sha3.h"

namespace keccak {

class SHA3_512 : public SHA3<512> {
public:
    explicit SHA3_512(uint8_t flag = 0);
};

} // namespace keccak

#endif //KECCAK_SHA3_512_H