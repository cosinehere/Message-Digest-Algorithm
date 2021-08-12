#include "pch.h"
#include "CMDA_SHA512.h"

#include "mdatemplates.h"

namespace mda {

#define RROT(a, b) r_rot<uint64_t>(a, b)

constexpr uint64_t c_sha512initvar[] = {
    0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull, 0x3c6ef372fe94f82bull,
    0xa54ff53a5f1d36f1ull, 0x510e527fade682d1ull, 0x9b05688c2b3e6c1full,
    0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull};

constexpr uint64_t k[] = {
    0x428a2f98d728ae22ull, 0x7137449123ef65cdull, 0xb5c0fbcfec4d3b2full,
    0xe9b5dba58189dbbcull, 0x3956c25bf348b538ull, 0x59f111f1b605d019ull,
    0x923f82a4af194f9bull, 0xab1c5ed5da6d8118ull, 0xd807aa98a3030242ull,
    0x12835b0145706fbeull, 0x243185be4ee4b28cull, 0x550c7dc3d5ffb4e2ull,
    0x72be5d74f27b896full, 0x80deb1fe3b1696b1ull, 0x9bdc06a725c71235ull,
    0xc19bf174cf692694ull, 0xe49b69c19ef14ad2ull, 0xefbe4786384f25e3ull,
    0x0fc19dc68b8cd5b5ull, 0x240ca1cc77ac9c65ull, 0x2de92c6f592b0275ull,
    0x4a7484aa6ea6e483ull, 0x5cb0a9dcbd41fbd4ull, 0x76f988da831153b5ull,
    0x983e5152ee66dfabull, 0xa831c66d2db43210ull, 0xb00327c898fb213full,
    0xbf597fc7beef0ee4ull, 0xc6e00bf33da88fc2ull, 0xd5a79147930aa725ull,
    0x06ca6351e003826full, 0x142929670a0e6e70ull, 0x27b70a8546d22ffcull,
    0x2e1b21385c26c926ull, 0x4d2c6dfc5ac42aedull, 0x53380d139d95b3dfull,
    0x650a73548baf63deull, 0x766a0abb3c77b2a8ull, 0x81c2c92e47edaee6ull,
    0x92722c851482353bull, 0xa2bfe8a14cf10364ull, 0xa81a664bbc423001ull,
    0xc24b8b70d0f89791ull, 0xc76c51a30654be30ull, 0xd192e819d6ef5218ull,
    0xd69906245565a910ull, 0xf40e35855771202aull, 0x106aa07032bbd1b8ull,
    0x19a4c116b8d2d0c8ull, 0x1e376c085141ab53ull, 0x2748774cdf8eeb99ull,
    0x34b0bcb5e19b48a8ull, 0x391c0cb3c5c95a63ull, 0x4ed8aa4ae3418acbull,
    0x5b9cca4f7763e373ull, 0x682e6ff3d6b2b8a3ull, 0x748f82ee5defb2fcull,
    0x78a5636f43172f60ull, 0x84c87814a1f0ab72ull, 0x8cc702081a6439ecull,
    0x90befffa23631e28ull, 0xa4506cebde82bde9ull, 0xbef9a3f7b2c67915ull,
    0xc67178f2e372532bull, 0xca273eceea26619cull, 0xd186b8c721c0c207ull,
    0xeada7dd6cde0eb1eull, 0xf57d4f7fee6ed178ull, 0x06f067aa72176fbaull,
    0x0a637dc5a2c898a6ull, 0x113f9804bef90daeull, 0x1b710b35131c471bull,
    0x28db77f523047d84ull, 0x32caab7b40c72493ull, 0x3c9ebe0a15c9bebcull,
    0x431d67c49c100d4cull, 0x4cc5d4becb3e42b6ull, 0x597f299cfc657e2aull,
    0x5fcb6fab3ad6faecull, 0x6c44198c4a475817ull};

CMDA_SHA512::CMDA_SHA512()
    : p_val(reinterpret_cast<const uint32_t *>(c_sha512initvar), 16) {
    p_salt = nullptr;
    p_saltlen = 0;

    buflen = 0;
    totbytes = 0;
}

CMDA_SHA512::~CMDA_SHA512() {
    if (p_salt != nullptr) {
        delete[] p_salt;
        p_salt = nullptr;
        p_saltlen = 0;
    }
}

void CMDA_SHA512::init() {
    p_val.init(reinterpret_cast<const uint32_t *>(c_sha512initvar), 16);

    if (p_salt != nullptr) {
        delete[] p_salt;
        p_salt = nullptr;
        p_saltlen = 0;
    }

    buflen = 0;
    totbytes = 0;
}

void CMDA_SHA512::set_salt(const uint8_t *salt, const size_t len) {
    if (p_salt != nullptr) {
        delete[] p_salt;
    }

    p_salt = new uint8_t[len];
    memcpy(p_salt, salt, sizeof(uint8_t) * len);
    p_saltlen = len;
}

bool CMDA_SHA512::update(const uint8_t *src, const size_t len) {
    size_t cnt = 0;
    while (cnt < len) {
        size_t bufleft =
            (len - cnt > 128 - buflen) ? (128 - buflen) : (len - cnt);
        memcpy(&buffer[buflen], src + cnt, bufleft * sizeof(uint8_t));
        cnt += bufleft;
        buflen += bufleft;

        if (buflen == 128) {
            transform();
            buflen = 0;
        }
    }

    totbytes += len;

    return true;
}

bool CMDA_SHA512::finish(_MDAVALUE &dst) {
    if (p_salt != nullptr) {
        update(p_salt, p_saltlen);
    }

    uint64_t totbits = totbytes << 3;
    ++totbytes;
    buffer[buflen] = 0x80;
    ++buflen;
    while ((totbytes & 0x7f) != 0x70) {
        ++totbytes;
        buffer[buflen] = 0x00;
        ++buflen;

        if (buflen == 128) {
            transform();
            buflen = 0;
        }
    }

    for (int i = 0; i < 8; ++i) {
        buffer[buflen + i] = 0;
    }
    for (int i = 8; i < 16; ++i) {
        buffer[buflen + i] = (totbits >> (120 - i * 8)) & 0xff;
    }
    buflen += 16;

    if (buflen == 128) {
        transform();
        buflen = 0;
    }

    dst = p_val;

    return true;
}

void CMDA_SHA512::transform() {
    uint64_t word[80];
    for (size_t j = 0; j < 16; ++j) {
        word[j] = (static_cast<uint64_t>(buffer[8 * j]) << 56) |
                  (static_cast<uint64_t>(buffer[8 * j + 1]) << 48) |
                  (static_cast<uint64_t>(buffer[8 * j + 2]) << 40) |
                  (static_cast<uint64_t>(buffer[8 * j + 3]) << 32) |
                  (static_cast<uint64_t>(buffer[8 * j + 4]) << 24) |
                  (static_cast<uint64_t>(buffer[8 * j + 5]) << 16) |
                  (static_cast<uint64_t>(buffer[8 * j + 6]) << 8) |
                  static_cast<uint64_t>(buffer[8 * j + 7]);
    }
    for (size_t j = 16; j < 80; ++j) {
        uint64_t s0 =
            RROT(word[j - 15], 1) ^ RROT(word[j - 15], 8) ^ (word[j - 15] >> 7);
        uint64_t s1 =
            RROT(word[j - 2], 19) ^ RROT(word[j - 2], 61) ^ (word[j - 2] >> 6);
        word[j] = word[j - 16] + s0 + word[j - 7] + s1;
    }

    uint64_t *p = reinterpret_cast<uint64_t *>(p_val.val);
    uint64_t a = p[0], b = p[1], c = p[2], d = p[3], e = p[4], f = p[5],
             g = p[6], h = p[7];

    for (size_t i = 0; i < 80; ++i) {
        uint64_t s1 = RROT(e, 14) ^ RROT(e, 18) ^ RROT(e, 41);
        uint64_t ch = (e & f) ^ (~e & g);
        uint64_t tmp1 = h + s1 + ch + k[i] + word[i];
        uint64_t s0 = RROT(a, 28) ^ RROT(a, 34) ^ RROT(a, 39);
        uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint64_t tmp2 = s0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + tmp1;
        d = c;
        c = b;
        b = a;
        a = tmp1 + tmp2;
    }

    p[0] += a;
    p[1] += b;
    p[2] += c;
    p[3] += d;
    p[4] += e;
    p[5] += f;
    p[6] += g;
    p[7] += h;
}

} // namespace mda
