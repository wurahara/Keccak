#include <gtest/gtest.h>
#include <array>

#include "sha3_256.h"
#include "sha3_384.h"
#include "sha3_512.h"

TEST(TestSha, SHA3_256_Basic_Keccak) {
    std::array<uint64_t, keccak::SHA3_256::SPONGE_WORDS> res = keccak::SHA3_256::hash_buffer("abc", 3, 1);

    EXPECT_EQ(res[0], 0x4fa945ea7a65034e);
    EXPECT_EQ(res[1], 0x67d6c826a87bd4c7);
    EXPECT_EQ(res[2], 0x36a0643ae3e6d1c0);
    EXPECT_EQ(res[3], 0x456c2da18ff544ec);
}

TEST(TestSha, SHA3_256_Basic_Keccak_2) {
    keccak::SHA3_256 sha3(1);
    sha3.update("\xcc", 1);
    std::array<uint64_t, keccak::SHA3_256::SPONGE_WORDS> res = sha3.finalize();

    EXPECT_EQ(std::memcmp(res.data(),
                          "\xee\xad\x6d\xbf\xc7\x34\x0a\x56\xca\xed\xc0\x44\x69\x6a\x16\x88"
                          "\x70\x54\x9a\x6a\x7f\x6f\x56\x96\x1e\x84\xa5\x4b\xd9\x97\x0b\x8a", 32), 0);
}

TEST(TestSha, SHA3_256_Basic_Keccak_3) {
    keccak::SHA3_256 sha3(1);
    sha3.update("\x41\xfb", 2);
    std::array<uint64_t, keccak::SHA3_256::SPONGE_WORDS> res = sha3.finalize();

    EXPECT_EQ(std::memcmp(res.data(),
                          "\xa8\xea\xce\xda\x4d\x47\xb3\x28\x1a\x79\x5a\xd9\xe1\xea\x21\x22"
                          "\xb4\x07\xba\xf9\xaa\xbc\xb9\xe1\x8b\x57\x17\xb7\x87\x35\x37\xd2", 32), 0);
}

TEST(TestSha, SHA3_256_Basic_Keccak_4) {
    keccak::SHA3_256 sha3(1);
    sha3.update("\x52\xa6\x08\xab\x21\xcc\xdd\x8a\x44\x57\xa5\x7e\xde\x78\x21\x76", 16);
    std::array<uint64_t, keccak::SHA3_256::SPONGE_WORDS> res = sha3.finalize();

    EXPECT_EQ(std::memcmp(res.data(),
                          "\x0e\x32\xde\xfa\x20\x71\xf0\xb5\xac\x0e\x6a\x10\x8b\x84\x2e\xd0"
                          "\xf1\xd3\x24\x97\x12\xf5\x8e\xe0\xdd\xf9\x56\xfe\x33\x2a\x5f\x95", 32), 0);
}

TEST(TestSha, SHA3_256_Basic_Keccak_5) {
    keccak::SHA3_256 sha3(1);
    sha3.update("\x43\x3c\x53\x03\x13\x16\x24\xc0\x02\x1d\x86\x8a\x30\x82\x54\x75"
                "\xe8\xd0\xbd\x30\x52\xa0\x22\x18\x03\x98\xf4\xca\x44\x23\xb9\x82"
                "\x14\xb6\xbe\xaa\xc2\x1c\x88\x07\xa2\xc3\x3f\x8c\x93\xbd\x42\xb0"
                "\x92\xcc\x1b\x06\xce\xdf\x32\x24\xd5\xed\x1e\xc2\x97\x84\x44\x4f"
                "\x22\xe0\x8a\x55\xaa\x58\x54\x2b\x52\x4b\x02\xcd\x3d\x5d\x5f\x69"
                "\x07\xaf\xe7\x1c\x5d\x74\x62\x22\x4a\x3f\x9d\x9e\x53\xe7\xe0\x84"
                "\x6d\xcb\xb4\xce", 100);
    std::array<uint64_t, keccak::SHA3_256::SPONGE_WORDS> res = sha3.finalize();

    EXPECT_EQ(std::memcmp(res.data(),
                          "\xce\x87\xa5\x17\x3b\xff\xd9\x23\x99\x22\x16\x58\xf8\x01\xd4\x5c"
                          "\x29\x4d\x90\x06\xee\x9f\x3f\x9d\x41\x9c\x8d\x42\x77\x48\xdc\x41", 32), 0);
}

TEST(TestSha, ExtremelyLongMessage) {
    int i = 16777216;
    keccak::SHA3_256 sha3(1);
    while (i--) {
        sha3.update("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno", 64);
    }
    auto res = sha3.finalize();

    EXPECT_EQ(std::memcmp(res.data(),
                          "\x5f\x31\x3c\x39\x96\x3d\xcf\x79\x2b\x54\x70\xd4\xad\xe9\xf3\xa3"
                          "\x56\xa3\xe4\x02\x17\x48\x69\x0a\x95\x83\x72\xe2\xb0\x6f\x82\xa4", 32), 0);
}

TEST(TestSha, SHA3_256_Empty_Buffer) {
    keccak::SHA3_256 sha3(0);
    auto res = sha3.finalize();
    constexpr uint8_t SHA3_256_EMPTY[256 / 8] = {
            0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
            0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
            0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
            0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a
    };
    EXPECT_EQ(std::memcmp(res.data(), SHA3_256_EMPTY, sizeof(SHA3_256_EMPTY)), 0);
}

TEST(TestSha, SHA3_256_Buffer) {
    auto res = keccak::SHA3_256::hash_buffer("abc", 3, 0);
    EXPECT_EQ(std::memcmp(res.data(),
                          "\x3a\x98\x5d\xa7\x4f\xe2\x25\xb2\x04\x5c\x17\x2d\x6b\xd3\x90\xbd"
                          "\x85\x5f\x08\x6e\x3e\x9d\x52\x5b\x46\xbf\xe2\x45\x11\x43\x15\x32", 32), 0);
}

TEST(TestSha, SHA3_256_Single_Buffer) {
    keccak::SHA3_256 sha3(0);
    uint8_t buf[200];
    std::memset(buf, 0xa3, sizeof(buf));
    sha3.update(buf, sizeof(buf));
    auto res = sha3.finalize();

    constexpr uint8_t SHA3_256_0xa3_200_TIMES[256 / 8] = {
            0x79, 0xf3, 0x8a, 0xde, 0xc5, 0xc2, 0x03, 0x07,
            0xa9, 0x8e, 0xf7, 0x6e, 0x83, 0x24, 0xaf, 0xbf,
            0xd4, 0x6c, 0xfd, 0x81, 0xb2, 0x2e, 0x39, 0x73,
            0xc6, 0x5f, 0xa1, 0xbd, 0x9d, 0xe3, 0x17, 0x87
    };

    EXPECT_EQ(std::memcmp(res.data(), SHA3_256_0xa3_200_TIMES, sizeof(SHA3_256_0xa3_200_TIMES)), 0);
}

TEST(TestSha, SHA3_256_Two_Steps) {
    keccak::SHA3_256 sha3(0);
    uint8_t buf[200];
    std::memset(buf, 0xa3, sizeof(buf));

    sha3.update(buf, sizeof(buf) / 2);
    sha3.update(buf + sizeof(buf) / 2, sizeof(buf) / 2);

    auto res = sha3.finalize();

    constexpr uint8_t SHA3_256_0xa3_200_TIMES[256 / 8] = {
            0x79, 0xf3, 0x8a, 0xde, 0xc5, 0xc2, 0x03, 0x07,
            0xa9, 0x8e, 0xf7, 0x6e, 0x83, 0x24, 0xaf, 0xbf,
            0xd4, 0x6c, 0xfd, 0x81, 0xb2, 0x2e, 0x39, 0x73,
            0xc6, 0x5f, 0xa1, 0xbd, 0x9d, 0xe3, 0x17, 0x87
    };

    EXPECT_EQ(std::memcmp(res.data(), SHA3_256_0xa3_200_TIMES, sizeof(SHA3_256_0xa3_200_TIMES)), 0);
}

TEST(TestSha, SHA3_256_200_Steps) {
    keccak::SHA3_256 sha3(0);

    int count = 200;
    while (count--) {
        sha3.update("\xa3", 1);
    }
    auto res = sha3.finalize();

    constexpr uint8_t SHA3_256_0xa3_200_TIMES[256 / 8] = {
            0x79, 0xf3, 0x8a, 0xde, 0xc5, 0xc2, 0x03, 0x07,
            0xa9, 0x8e, 0xf7, 0x6e, 0x83, 0x24, 0xaf, 0xbf,
            0xd4, 0x6c, 0xfd, 0x81, 0xb2, 0x2e, 0x39, 0x73,
            0xc6, 0x5f, 0xa1, 0xbd, 0x9d, 0xe3, 0x17, 0x87
    };

    EXPECT_EQ(std::memcmp(res.data(), SHA3_256_0xa3_200_TIMES, sizeof(SHA3_256_0xa3_200_TIMES)), 0);
}

TEST(TestSha, SHA3_256_135_Bytes) {
    keccak::SHA3_256 sha3(0);
    sha3.update("\xb7\x71\xd5\xce\xf5\xd1\xa4\x1a\x93\xd1\x56\x43\xd7\x18\x1d\x2a"
                "\x2e\xf0\xa8\xe8\x4d\x91\x81\x2f\x20\xed\x21\xf1\x47\xbe\xf7\x32"
                "\xbf\x3a\x60\xef\x40\x67\xc3\x73\x4b\x85\xbc\x8c\xd4\x71\x78\x0f"
                "\x10\xdc\x9e\x82\x91\xb5\x83\x39\xa6\x77\xb9\x60\x21\x8f\x71\xe7"
                "\x93\xf2\x79\x7a\xea\x34\x94\x06\x51\x28\x29\x06\x5d\x37\xbb\x55"
                "\xea\x79\x6f\xa4\xf5\x6f\xd8\x89\x6b\x49\xb2\xcd\x19\xb4\x32\x15"
                "\xad\x96\x7c\x71\x2b\x24\xe5\x03\x2d\x06\x52\x32\xe0\x2c\x12\x74"
                "\x09\xd2\xed\x41\x46\xb9\xd7\x5d\x76\x3d\x52\xdb\x98\xd9\x49\xd3"
                "\xb0\xfe\xd6\xa8\x05\x2f\xbb", 1080 / 8);
    auto res = sha3.finalize();
    EXPECT_EQ(std::memcmp(res.data(),
                          "\xa1\x9e\xee\x92\xbb\x20\x97\xb6\x4e\x82\x3d\x59\x77\x98\xaa\x18"
                          "\xbe\x9b\x7c\x73\x6b\x80\x59\xab\xfd\x67\x79\xac\x35\xac\x81\xb5", 32), 0);
}

TEST(TestSha, SHA3_384_Single_Buffer) {
    uint8_t buf[200];
    std::memset(buf, 0xa3, sizeof(buf));

    keccak::SHA3_384 sha3(0);
    sha3.update(buf, sizeof(buf));
    auto res = sha3.finalize();

    static const uint8_t SHA3_384_0xa3_200_TIMES[384 / 8] = {
            0x18, 0x81, 0xde, 0x2c, 0xa7, 0xe4, 0x1e, 0xf9,
            0x5d, 0xc4, 0x73, 0x2b, 0x8f, 0x5f, 0x00, 0x2b,
            0x18, 0x9c, 0xc1, 0xe4, 0x2b, 0x74, 0x16, 0x8e,
            0xd1, 0x73, 0x26, 0x49, 0xce, 0x1d, 0xbc, 0xdd,
            0x76, 0x19, 0x7a, 0x31, 0xfd, 0x55, 0xee, 0x98,
            0x9f, 0x2d, 0x70, 0x50, 0xdd, 0x47, 0x3e, 0x8f
    };

    EXPECT_EQ(std::memcmp(res.data(), SHA3_384_0xa3_200_TIMES, sizeof(SHA3_384_0xa3_200_TIMES)), 0);
}

TEST(TestSha, SHA3_384_Two_Steps) {
    uint8_t buf[200];
    std::memset(buf, 0xa3, sizeof(buf));

    keccak::SHA3_384 sha3(0);
    sha3.update(buf, sizeof(buf) / 2);
    sha3.update(buf + sizeof(buf) / 2, sizeof(buf) / 2);
    auto res = sha3.finalize();

    static const uint8_t SHA3_384_0xa3_200_TIMES[384 / 8] = {
            0x18, 0x81, 0xde, 0x2c, 0xa7, 0xe4, 0x1e, 0xf9,
            0x5d, 0xc4, 0x73, 0x2b, 0x8f, 0x5f, 0x00, 0x2b,
            0x18, 0x9c, 0xc1, 0xe4, 0x2b, 0x74, 0x16, 0x8e,
            0xd1, 0x73, 0x26, 0x49, 0xce, 0x1d, 0xbc, 0xdd,
            0x76, 0x19, 0x7a, 0x31, 0xfd, 0x55, 0xee, 0x98,
            0x9f, 0x2d, 0x70, 0x50, 0xdd, 0x47, 0x3e, 0x8f
    };

    EXPECT_EQ(std::memcmp(res.data(), SHA3_384_0xa3_200_TIMES, sizeof(SHA3_384_0xa3_200_TIMES)), 0);
}

TEST(TestSha, SHA3_384_200_Steps) {
    keccak::SHA3_384 sha3(0);

    int count = 200;
    while (count--) {
        sha3.update("\xa3", 1);
    }
    auto res = sha3.finalize();

    constexpr uint8_t SHA3_384_0xa3_200_TIMES[384 / 8] = {
            0x18, 0x81, 0xde, 0x2c, 0xa7, 0xe4, 0x1e, 0xf9,
            0x5d, 0xc4, 0x73, 0x2b, 0x8f, 0x5f, 0x00, 0x2b,
            0x18, 0x9c, 0xc1, 0xe4, 0x2b, 0x74, 0x16, 0x8e,
            0xd1, 0x73, 0x26, 0x49, 0xce, 0x1d, 0xbc, 0xdd,
            0x76, 0x19, 0x7a, 0x31, 0xfd, 0x55, 0xee, 0x98,
            0x9f, 0x2d, 0x70, 0x50, 0xdd, 0x47, 0x3e, 0x8f
    };

    EXPECT_EQ(std::memcmp(res.data(), SHA3_384_0xa3_200_TIMES, sizeof(SHA3_384_0xa3_200_TIMES)), 0);
}

TEST(TestSha, SHA3_512_Single_Buffer) {
    uint8_t buf[200];
    std::memset(buf, 0xa3, sizeof(buf));

    keccak::SHA3_512 sha3(0);
    sha3.update(buf, sizeof(buf));
    auto res = sha3.finalize();

    constexpr uint8_t SHA3_512_0xa3_200_TIMES[512 / 8] = {
            0xe7, 0x6d, 0xfa, 0xd2, 0x20, 0x84, 0xa8, 0xb1,
            0x46, 0x7f, 0xcf, 0x2f, 0xfa, 0x58, 0x36, 0x1b,
            0xec, 0x76, 0x28, 0xed, 0xf5, 0xf3, 0xfd, 0xc0,
            0xe4, 0x80, 0x5d, 0xc4, 0x8c, 0xae, 0xec, 0xa8,
            0x1b, 0x7c, 0x13, 0xc3, 0x0a, 0xdf, 0x52, 0xa3,
            0x65, 0x95, 0x84, 0x73, 0x9a, 0x2d, 0xf4, 0x6b,
            0xe5, 0x89, 0xc5, 0x1c, 0xa1, 0xa4, 0xa8, 0x41,
            0x6d, 0xf6, 0x54, 0x5a, 0x1c, 0xe8, 0xba, 0x00
    };

    EXPECT_EQ(std::memcmp(res.data(), SHA3_512_0xa3_200_TIMES, sizeof(SHA3_512_0xa3_200_TIMES)), 0);
}

TEST(TestSha, SHA3_512_Two_Steps) {
    uint8_t buf[200];
    std::memset(buf, 0xa3, sizeof(buf));

    keccak::SHA3_512 sha3(0);
    sha3.update(buf, sizeof(buf) / 2);
    sha3.update(buf + sizeof(buf) / 2, sizeof(buf) / 2);
    auto res = sha3.finalize();

    constexpr uint8_t SHA3_512_0xa3_200_TIMES[512 / 8] = {
            0xe7, 0x6d, 0xfa, 0xd2, 0x20, 0x84, 0xa8, 0xb1,
            0x46, 0x7f, 0xcf, 0x2f, 0xfa, 0x58, 0x36, 0x1b,
            0xec, 0x76, 0x28, 0xed, 0xf5, 0xf3, 0xfd, 0xc0,
            0xe4, 0x80, 0x5d, 0xc4, 0x8c, 0xae, 0xec, 0xa8,
            0x1b, 0x7c, 0x13, 0xc3, 0x0a, 0xdf, 0x52, 0xa3,
            0x65, 0x95, 0x84, 0x73, 0x9a, 0x2d, 0xf4, 0x6b,
            0xe5, 0x89, 0xc5, 0x1c, 0xa1, 0xa4, 0xa8, 0x41,
            0x6d, 0xf6, 0x54, 0x5a, 0x1c, 0xe8, 0xba, 0x00
    };

    EXPECT_EQ(std::memcmp(res.data(), SHA3_512_0xa3_200_TIMES, sizeof(SHA3_512_0xa3_200_TIMES)), 0);
}

TEST(TestSha, SHA3_512_200_Steps) {
    keccak::SHA3_512 sha3(0);

    int count = 200;
    while (count--) {
        sha3.update("\xa3", 1);
    }
    auto res = sha3.finalize();

    constexpr uint8_t SHA3_512_0xa3_200_TIMES[512 / 8] = {
            0xe7, 0x6d, 0xfa, 0xd2, 0x20, 0x84, 0xa8, 0xb1,
            0x46, 0x7f, 0xcf, 0x2f, 0xfa, 0x58, 0x36, 0x1b,
            0xec, 0x76, 0x28, 0xed, 0xf5, 0xf3, 0xfd, 0xc0,
            0xe4, 0x80, 0x5d, 0xc4, 0x8c, 0xae, 0xec, 0xa8,
            0x1b, 0x7c, 0x13, 0xc3, 0x0a, 0xdf, 0x52, 0xa3,
            0x65, 0x95, 0x84, 0x73, 0x9a, 0x2d, 0xf4, 0x6b,
            0xe5, 0x89, 0xc5, 0x1c, 0xa1, 0xa4, 0xa8, 0x41,
            0x6d, 0xf6, 0x54, 0x5a, 0x1c, 0xe8, 0xba, 0x00
    };

    EXPECT_EQ(std::memcmp(res.data(), SHA3_512_0xa3_200_TIMES, sizeof(SHA3_512_0xa3_200_TIMES)), 0);
}

TEST(TestSha, Keccak_F_1600) {
    constexpr std::array<uint64_t, keccak::util::P_LEN> state_first = {
            0xF1258F7940E1DDE7, 0x84D5CCF933C0478A, 0xD598261EA65AA9EE, 0xBD1547306F80494D, 0x8B284E056253D057,
            0xFF97A42D7F8E6FD4, 0x90FEE5A0A44647C4, 0x8C5BDA0CD6192E76, 0xAD30A6F71B19059C, 0x30935AB7D08FFC64,
            0xEB5AA93F2317D635, 0xA9A6E6260D712103, 0x81A57C16DBCF555F, 0x43B831CD0347C826, 0x01F22F1A11A5569F,
            0x05E5635A21D9AE61, 0x64BEFEF28CC970F2, 0x613670957BC46611, 0xB87C5A554FD00ECB, 0x8C3EE88A1CCF32C8,
            0x940C7922AE3A2614, 0x1841F924A2C509E4, 0x16F53526E70465C2, 0x75F644E97F30A13B, 0xEAF1FF7B5CECA249,
    };
    constexpr std::array<uint64_t, keccak::util::P_LEN> state_second = {
            0x2D5C954DF96ECB3C, 0x6A332CD07057B56D, 0x093D8D1270D76B6C, 0x8A20D9B25569D094, 0x4F9C4F99E5E7F156,
            0xF957B9A2DA65FB38, 0x85773DAE1275AF0D, 0xFAF4F247C3D810F7, 0x1F1B9EE6F79A8759, 0xE4FECC0FEE98B425,
            0x68CE61B6B9CE68A1, 0xDEEA66C4BA8F974F, 0x33C43D836EAFB1F5, 0xE00654042719DBD9, 0x7CF8A9F009831265,
            0xFD5449A6BF174743, 0x97DDAD33D8994B40, 0x48EAD5FC5D0BE774, 0xE3B8C8EE55B7B03C, 0x91A0226E649E42E9,
            0x900E3129E7BADD7B, 0x202A9EC5FAA3CCE8, 0x5B3402464E1C3DB6, 0x609F4E62A44C1059, 0x20D06CD26A8FBF5C,
    };

    std::array<uint64_t, keccak::util::P_LEN> state = {0};

    keccak::util::keccak_f(state);
    EXPECT_EQ(state, state_first);

    keccak::util::keccak_f(state);
    EXPECT_EQ(state, state_second);
}