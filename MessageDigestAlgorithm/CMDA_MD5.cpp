#include "pch.h"
#include "CMDA_MD5.h"

#include "mdatemplates.h"

namespace mda {

#define LROT(a,b) l_rot<uint32_t>(a,b)

constexpr uint32_t c_md5initvar[] = { 0x67452301ul, 0xEFCDAB89ul, 0x98BADCFEul, 0x10325476ul };

inline uint32_t F(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | ((~x) & z); }
inline uint32_t G(uint32_t x, uint32_t y, uint32_t z) { return (x & z) | (y & (~z)); }
inline uint32_t H(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }
inline uint32_t I(uint32_t x, uint32_t y, uint32_t z) { return y ^ (x | (~z)); }

inline void FF(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d, uint32_t Mj, uint32_t s, uint32_t ti) {
    a += F(b, c, d) + Mj + ti; a = LROT(a, s); a += b;
}
inline void GG(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d, uint32_t Mj, uint32_t s, uint32_t ti) {
    a += G(b, c, d) + Mj + ti; a = LROT(a, s); a += b;
}
inline void HH(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d, uint32_t Mj, uint32_t s, uint32_t ti) {
    a += H(b, c, d) + Mj + ti; a = LROT(a, s); a += b;
}
inline void II(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d, uint32_t Mj, uint32_t s, uint32_t ti) {
    a += I(b, c, d) + Mj + ti; a = LROT(a, s); a += b;
}

inline void ROUND1(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d, uint32_t* M)
{
    FF(a, b, c, d, M[0], 7, 0xd76aa478ul);
    FF(d, a, b, c, M[1], 12, 0xe8c7b756ul);
    FF(c, d, a, b, M[2], 17, 0x242070dbul);
    FF(b, c, d, a, M[3], 22, 0xc1bdceeeul);
    FF(a, b, c, d, M[4], 7, 0xf57c0faful);
    FF(d, a, b, c, M[5], 12, 0x4787c62aul);
    FF(c, d, a, b, M[6], 17, 0xa8304613ul);
    FF(b, c, d, a, M[7], 22, 0xfd469501ul);
    FF(a, b, c, d, M[8], 7, 0x698098d8ul);
    FF(d, a, b, c, M[9], 12, 0x8b44f7aful);
    FF(c, d, a, b, M[10], 17, 0xffff5bb1ul);
    FF(b, c, d, a, M[11], 22, 0x895cd7beul);
    FF(a, b, c, d, M[12], 7, 0x6b901122ul);
    FF(d, a, b, c, M[13], 12, 0xfd987193ul);
    FF(c, d, a, b, M[14], 17, 0xa679438eul);
    FF(b, c, d, a, M[15], 22, 0x49b40821ul);
}

inline void ROUND2(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d, uint32_t* M)
{
    GG(a, b, c, d, M[1], 5, 0xf61e2562ul);
    GG(d, a, b, c, M[6], 9, 0xc040b340ul);
    GG(c, d, a, b, M[11], 14, 0x265e5a51ul);
    GG(b, c, d, a, M[0], 20, 0xe9b6c7aaul);
    GG(a, b, c, d, M[5], 5, 0xd62f105dul);
    GG(d, a, b, c, M[10], 9, 0x02441453ul);
    GG(c, d, a, b, M[15], 14, 0xd8a1e681ul);
    GG(b, c, d, a, M[4], 20, 0xe7d3fbc8ul);
    GG(a, b, c, d, M[9], 5, 0x21e1cde6ul);
    GG(d, a, b, c, M[14], 9, 0xc33707d6ul);
    GG(c, d, a, b, M[3], 14, 0xf4d50d87ul);
    GG(b, c, d, a, M[8], 20, 0x455a14edul);
    GG(a, b, c, d, M[13], 5, 0xa9e3e905ul);
    GG(d, a, b, c, M[2], 9, 0xfcefa3f8ul);
    GG(c, d, a, b, M[7], 14, 0x676f02d9ul);
    GG(b, c, d, a, M[12], 20, 0x8d2a4c8aul);
}

inline void ROUND3(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d, uint32_t* M)
{
    HH(a, b, c, d, M[5], 4, 0xfffa3942ul);
    HH(d, a, b, c, M[8], 11, 0x8771f681ul);
    HH(c, d, a, b, M[11], 16, 0x6d9d6122ul);
    HH(b, c, d, a, M[14], 23, 0xfde5380cul);
    HH(a, b, c, d, M[1], 4, 0xa4beea44ul);
    HH(d, a, b, c, M[4], 11, 0x4bdecfa9ul);
    HH(c, d, a, b, M[7], 16, 0xf6bb4b60ul);
    HH(b, c, d, a, M[10], 23, 0xbebfbc70ul);
    HH(a, b, c, d, M[13], 4, 0x289b7ec6ul);
    HH(d, a, b, c, M[0], 11, 0xeaa127faul);
    HH(c, d, a, b, M[3], 16, 0xd4ef3085ul);
    HH(b, c, d, a, M[6], 23, 0x04881d05ul);
    HH(a, b, c, d, M[9], 4, 0xd9d4d039ul);
    HH(d, a, b, c, M[12], 11, 0xe6db99e5ul);
    HH(c, d, a, b, M[15], 16, 0x1fa27cf8ul);
    HH(b, c, d, a, M[2], 23, 0xc4ac5665ul);
}

inline void ROUND4(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d, uint32_t* M)
{
    II(a, b, c, d, M[0], 6, 0xf4292244ul);
    II(d, a, b, c, M[7], 10, 0x432aff97ul);
    II(c, d, a, b, M[14], 15, 0xab9423a7ul);
    II(b, c, d, a, M[5], 21, 0xfc93a039ul);
    II(a, b, c, d, M[12], 6, 0x655b59c3ul);
    II(d, a, b, c, M[3], 10, 0x8f0ccc92ul);
    II(c, d, a, b, M[10], 15, 0xffeff47dul);
    II(b, c, d, a, M[1], 21, 0x85845dd1ul);
    II(a, b, c, d, M[8], 6, 0x6fa87e4ful);
    II(d, a, b, c, M[15], 10, 0xfe2ce6e0ul);
    II(c, d, a, b, M[6], 15, 0xa3014314ul);
    II(b, c, d, a, M[13], 21, 0x4e0811a1ul);
    II(a, b, c, d, M[4], 6, 0xf7537e82ul);
    II(d, a, b, c, M[11], 10, 0xbd3af235ul);
    II(c, d, a, b, M[2], 15, 0x2ad7d2bbul);
    II(b, c, d, a, M[9], 21, 0xeb86d391ul);
}

CMDA_MD5::CMDA_MD5()
    : p_val(c_md5initvar, 4)
{
    p_salt = nullptr;
    p_saltlen = 0;

    buflen = 0;
    totbytes = 0;
}

CMDA_MD5::~CMDA_MD5()
{
    if (p_salt != nullptr)
    {
        delete[] p_salt;
        p_salt = nullptr;
        p_saltlen = 0;
    }
}

void CMDA_MD5::init()
{
    p_val.init(c_md5initvar, 4);

    if (p_salt != nullptr)
    {
        delete[] p_salt;
        p_salt = nullptr;
        p_saltlen = 0;
    }

    buflen = 0;
    totbytes = 0;
}

void CMDA_MD5::set_salt(const uint8_t* salt, const size_t len)
{
    if (p_salt != nullptr)
    {
        delete[] p_salt;
    }

    p_salt = new uint8_t[len];
    memcpy(p_salt, salt, sizeof(uint8_t)*len);
    p_saltlen = len;
}

bool CMDA_MD5::update(const uint8_t* src, const size_t len)
{
    size_t cnt = 0;
    while (cnt < len)
    {
        size_t bufleft = (len - cnt > 64 - buflen) ? (64 - buflen) : (len - cnt);
        memcpy(&buffer[buflen], src + cnt, bufleft * sizeof(uint8_t));
        cnt += bufleft;
        buflen += bufleft;

        if (buflen == 64)
        {
            transform();
            buflen = 0;
        }
    }

    totbytes += len;

    return true;
}

bool CMDA_MD5::finish(_MDAVALUE& dst)
{
    if (p_salt != nullptr)
    {
        update(p_salt, p_saltlen);
    }

    uint64_t totbits = totbytes << 3;
    ++totbytes;
    buffer[buflen] = 0x80;
    ++buflen;
    while ((totbytes & 0x3f) != 0x38)
    {
        ++totbytes;
        buffer[buflen] = 0x00;
        ++buflen;

        if (buflen == 64)
        {
            transform();
            buflen = 0;
        }
    }

    for (int i = 0; i < 8; ++i)
    {
        buffer[buflen + i] = (totbits >> (i * 8)) & 0xff;
    }
    buflen += 8;

    if (buflen == 64)
    {
        transform();
        buflen = 0;
    }

    dst = p_val;

    return true;
}

void CMDA_MD5::transform()
{
    uint32_t a = p_val.val[0], b = p_val.val[1], c = p_val.val[2], d = p_val.val[3];
    uint32_t* pbuf = reinterpret_cast<uint32_t*>(buffer);

    ROUND1(a, b, c, d, pbuf);
    ROUND2(a, b, c, d, pbuf);
    ROUND3(a, b, c, d, pbuf);
    ROUND4(a, b, c, d, pbuf);

    p_val.val[0] += a;
    p_val.val[1] += b;
    p_val.val[2] += c;
    p_val.val[3] += d;
}

}
