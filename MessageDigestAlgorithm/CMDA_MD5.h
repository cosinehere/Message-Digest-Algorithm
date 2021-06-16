#pragma once

#include "MDAdefines.h"

constexpr uint32_t c_md5initvar[] = { 0x67452301UL, 0xEFCDAB89UL, 0x98BADCFEUL, 0x10325476UL };

#define F(x, y, z) (((x) & (y)) | ((~(x)) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~(z))))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~(z))))

#define FF(a, b, c, d, Mj , s, ti) { a += F(b, c, d) + Mj + ti; a = (a<<s) | (a>>(32-s)); a += b; }
#define GG(a, b, c, d, Mj , s, ti) { a += G(b, c, d) + Mj + ti; a = (a<<s) | (a>>(32-s)); a += b; }
#define HH(a, b, c, d, Mj , s, ti) { a += H(b, c, d) + Mj + ti; a = (a<<s) | (a>>(32-s)); a += b; }
#define II(a, b, c, d, Mj , s, ti) { a += I(b, c, d) + Mj + ti; a = (a<<s) | (a>>(32-s)); a += b; }

#define ROUND1(a, b, c, d, M) { \
	FF(a ,b ,c ,d ,M[0] ,7 ,0xd76aa478); \
	FF(d, a, b, c, M[1], 12, 0xe8c7b756); \
	FF(c, d, a, b, M[2], 17, 0x242070db); \
	FF(b, c, d, a, M[3], 22, 0xc1bdceee); \
	FF(a, b, c, d, M[4], 7, 0xf57c0faf); \
	FF(d, a, b, c, M[5], 12, 0x4787c62a); \
	FF(c, d, a, b, M[6], 17, 0xa8304613); \
	FF(b, c, d, a, M[7], 22, 0xfd469501); \
	FF(a, b, c, d, M[8], 7, 0x698098d8); \
	FF(d, a, b, c, M[9], 12, 0x8b44f7af); \
	FF(c, d, a, b, M[10], 17, 0xffff5bb1); \
	FF(b, c, d, a, M[11], 22, 0x895cd7be); \
	FF(a, b, c, d, M[12], 7, 0x6b901122); \
	FF(d, a, b, c, M[13], 12, 0xfd987193); \
	FF(c, d, a, b, M[14], 17, 0xa679438e); \
	FF(b, c, d, a, M[15], 22, 0x49b40821); \
}

#define ROUND2(a, b, c, d, M) { \
	GG(a, b, c, d, M[1], 5, 0xf61e2562); \
	GG(d, a, b, c, M[6], 9, 0xc040b340); \
	GG(c, d, a, b, M[11], 14, 0x265e5a51); \
	GG(b, c, d, a, M[0], 20, 0xe9b6c7aa); \
	GG(a, b, c, d, M[5], 5, 0xd62f105d); \
	GG(d, a, b, c, M[10], 9, 0x02441453); \
	GG(c, d, a, b, M[15], 14, 0xd8a1e681); \
	GG(b, c, d, a, M[4], 20, 0xe7d3fbc8); \
	GG(a, b, c, d, M[9], 5, 0x21e1cde6); \
	GG(d, a, b, c, M[14], 9, 0xc33707d6); \
	GG(c, d, a, b, M[3], 14, 0xf4d50d87); \
	GG(b, c, d, a, M[8], 20, 0x455a14ed); \
	GG(a, b, c, d, M[13], 5, 0xa9e3e905); \
	GG(d, a, b, c, M[2], 9, 0xfcefa3f8); \
	GG(c, d, a, b, M[7], 14, 0x676f02d9); \
	GG(b, c, d, a, M[12], 20, 0x8d2a4c8a); \
}

#define ROUND3(a, b, c, d, M) { \
	HH(a, b, c, d, M[5], 4, 0xfffa3942); \
	HH(d, a, b, c, M[8], 11, 0x8771f681); \
	HH(c, d, a, b, M[11], 16, 0x6d9d6122); \
	HH(b, c, d, a, M[14], 23, 0xfde5380c); \
	HH(a, b, c, d, M[1], 4, 0xa4beea44); \
	HH(d, a, b, c, M[4], 11, 0x4bdecfa9); \
	HH(c, d, a, b, M[7], 16, 0xf6bb4b60); \
	HH(b, c, d, a, M[10], 23, 0xbebfbc70); \
	HH(a, b, c, d, M[13], 4, 0x289b7ec6); \
	HH(d, a, b, c, M[0], 11, 0xeaa127fa); \
	HH(c, d, a, b, M[3], 16, 0xd4ef3085); \
	HH(b, c, d, a, M[6], 23, 0x04881d05); \
	HH(a, b, c, d, M[9], 4, 0xd9d4d039); \
	HH(d, a, b, c, M[12], 11, 0xe6db99e5); \
	HH(c, d, a, b, M[15], 16, 0x1fa27cf8); \
	HH(b, c, d, a, M[2], 23, 0xc4ac5665); \
}

#define ROUND4(a, b, c, d, M) { \
	II(a, b, c, d, M[0], 6, 0xf4292244); \
	II(d, a, b, c, M[7], 10, 0x432aff97); \
	II(c, d, a, b, M[14], 15, 0xab9423a7); \
	II(b, c, d, a, M[5], 21, 0xfc93a039); \
	II(a, b, c, d, M[12], 6, 0x655b59c3); \
	II(d, a, b, c, M[3], 10, 0x8f0ccc92); \
	II(c, d, a, b, M[10], 15, 0xffeff47d); \
	II(b, c, d, a, M[1], 21, 0x85845dd1); \
	II(a, b, c, d, M[8], 6, 0x6fa87e4f); \
	II(d, a, b, c, M[15], 10, 0xfe2ce6e0); \
	II(c, d, a, b, M[6], 15, 0xa3014314); \
	II(b, c, d, a, M[13], 21, 0x4e0811a1); \
	II(a, b, c, d, M[4], 6, 0xf7537e82); \
	II(d, a, b, c, M[11], 10, 0xbd3af235); \
	II(c, d, a, b, M[2], 15, 0x2ad7d2bb); \
	II(b, c, d, a, M[9], 21, 0xeb86d391); \
}

class CMDA_MD5 :
	public CMDA_Base
{
public:
	CMDA_MD5();
	~CMDA_MD5();

	virtual void init();
	virtual void set_salt(const uint8_t* salt, const uint32_t len);
	virtual bool update(const uint8_t* src, const uint64_t len);
	virtual bool finish(_MDAVALUE& dst);

private:
	_MDAVALUE p_val;

	uint8_t* p_salt;
	uint32_t p_saltlen;

	uint8_t buffer[64];
	uint64_t buflen;

	uint64_t totbits;

	void transform();
};
