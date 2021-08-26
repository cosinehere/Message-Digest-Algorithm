#include "pch.h"
#include "CMDA_SM3.h"

#include "mdatemplates.h"

namespace mda {

#define LROT(a, b) l_rot<uint32_t>(a, b)

constexpr uint32_t c_sm3initvar[] = { 0x7380166ful, 0x4914b2b9ul, 0x172442d7ul, 0xda8a0600ul, 0xa96f30bcul, 0x163138aaul, 0xe38dee4dul, 0xb0fb0e4eul };

constexpr uint32_t T[] = { 0x79cc4519ul, 0x7a879d8aul };

CMDA_SM3::CMDA_SM3() : p_val(c_sm3initvar, 8) {
    p_salt = nullptr;
    p_saltlen = 0;

    buflen = 0;
    totbytes = 0;
}

CMDA_SM3::~CMDA_SM3() {
    if (p_salt != nullptr) {
        delete[] p_salt;
        p_salt = nullptr;
        p_saltlen = 0;
    }
}

void CMDA_SM3::init() {
    p_val.init(c_sm3initvar, 8);

    if (p_salt != nullptr) {
        delete[] p_salt;
        p_salt = nullptr;
        p_saltlen = 0;
    }

    buflen = 0;
    totbytes = 0;
}

void CMDA_SM3::set_salt(const uint8_t *salt, const size_t len) {
    if (p_salt != nullptr) {
        delete[] p_salt;
    }

    p_salt = new uint8_t[len];
    memcpy(p_salt, salt, sizeof(uint8_t) * len);
    p_saltlen = len;
}

bool CMDA_SM3::update(const uint8_t *src, const size_t len) {
    size_t cnt = 0;
    while (cnt < len) {
        size_t bufleft =
            (len - cnt > 64 - buflen) ? (64 - buflen) : (len - cnt);
        memcpy(&buffer[buflen], src + cnt, bufleft * sizeof(uint8_t));
        cnt += bufleft;
        buflen += bufleft;

        if (buflen == 64) {
            transform();
            buflen = 0;
        }
    }

    totbytes += len;

    return true;
}

bool CMDA_SM3::finish(_MDACTX &dst) {
    if (p_salt != nullptr) {
        update(p_salt, p_saltlen);
    }

    uint64_t totbits = totbytes << 3;
    ++totbytes;
    buffer[buflen] = 0x80;
    ++buflen;
    while ((totbytes & 0x3f) != 0x38) {
        ++totbytes;
        buffer[buflen] = 0x00;
        ++buflen;

        if (buflen == 64) {
            transform();
            buflen = 0;
        }
    }

    for (int i = 0; i < 8; ++i) {
        buffer[buflen + 7 - i] = (totbits >> (i * 8)) & 0xff;
    }
    buflen += 8;

    if (buflen == 64) {
        transform();
        buflen = 0;
    }

    dst = p_val;

    return true;
}

inline uint32_t FF(size_t j, uint32_t x, uint32_t y, uint32_t z) {
    if (j < 16) {
        return x ^ y ^ z;
    }
    
    return (x & y) | (x & z) | (y & z);
}

inline uint32_t GG(size_t j, uint32_t x, uint32_t y, uint32_t z) {
    if (j < 16) {
        return x ^ y ^ z;
    }

    return (x & y) | ((~x) & z);
}

inline uint32_t P0(uint32_t x) {
    return x ^ LROT(x, 9) ^ LROT(x, 17);
}

inline uint32_t P1(uint32_t x) {
    return x ^ LROT(x, 15) ^ LROT(x, 23);
}

void CMDA_SM3::transform() {
    uint32_t word[68];
    uint32_t word1[64];

    for (size_t j = 0; j < 16; ++j) {
        word[j] = buffer[4 * j + 0] << 24 | buffer[4 * j + 1] << 16 |
                  buffer[4 * j + 2] << 8 | buffer[4 * j + 3];
    }

    for (size_t j = 16; j < 68; ++j) {
        word[j] = P1(word[j - 16] ^ word[j - 9] ^ LROT(word[j - 3], 15)) ^ LROT(word[j - 13], 7) ^ word[j - 6];
    }
    for (size_t j = 0; j < 64; ++j) {
        word1[j] = word[j] ^ word[j + 4];
    }

    uint32_t a = p_val.val[0], b = p_val.val[1], c = p_val.val[2], d = p_val.val[3],
        e = p_val.val[4], f = p_val.val[5], g = p_val.val[6], h = p_val.val[7];

    for (size_t j = 0; j < 64; ++j) {
        uint32_t ss1 = LROT(LROT(a, 12) + e + LROT(T[(j < 16) ? 0 : 1], j), 7);
        uint32_t ss2 = ss1 ^ LROT(a, 12);
        uint32_t tt1 = FF(j, a, b, c) + d + ss2 + word1[j];
        uint32_t tt2 = GG(j, e, f, g) + h + ss1 + word[j];
        d = c;
        c = LROT(b, 9);
        b = a;
        a = tt1;
        h = g;
        g = LROT(f, 19);
        f = e;
        e = P0(tt2);
    }

    p_val.val[0] ^= a;
    p_val.val[1] ^= b;
    p_val.val[2] ^= c;
    p_val.val[3] ^= d;
    p_val.val[4] ^= e;
    p_val.val[5] ^= f;
    p_val.val[6] ^= g;
    p_val.val[7] ^= h;
}

} // namespace mda
