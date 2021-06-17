#pragma once

#include "MDAdefines.h"

constexpr uint32_t c_sha1initvar[] = { 0x67452301UL, 0xEFCDAB89UL, 0x98BADCFEUL, 0x10325476UL, 0xC3D2E1F0UL };

inline uint32_t left_rotate(uint32_t a, uint32_t b)
{
	return (a << b) | (a >> (32 - b));
}

#define ROUND1(a,b,c,d,f,k) { f = ((b) & (c)) | ((~(b)) & (d)); k = 0x5A827999UL; }
//#define ROUND1(a,b,c,d,f,k) { f = (d) ^ ((b) & ((c) ^ (d))); k = 0x5A827999UL; }	//Alternative
#define ROUND2(a,b,c,d,f,k) { f = (b) ^ (c) ^ (d); k = 0x6ED9EBA1UL; }
#define ROUND3(a,b,c,d,f,k) { f = ((b) & (c)) | ((b) & (d)) | ((c) & (d)); k = 0x8F1BBCDCUL; }
//#define ROUND3(a,b,c,d,f,k) { f = ((b) & (c)) | ((d) & ((b) | (c))); k = 0x8F1BBCDCUL; }	//Alternative
#define ROUND4(a,b,c,d,f,k) { f = (b) ^ (c) ^ (d); k = 0xCA62C1D6UL; }

class CMDA_SHA1 :
	public CMDA_Base
{
public:
	CMDA_SHA1();
	~CMDA_SHA1();

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

	uint64_t totbytes;

	void transform();
};

