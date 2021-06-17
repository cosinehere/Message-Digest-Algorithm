#include "pch.h"
#include "CMDA_SHA256.h"

constexpr uint32_t c_sha256initvar[] = 
	{ 0x6a09e667UL, 0xbb67ae85UL, 0x3c6ef372UL, 0xa54ff53aUL, 0x510e527fUL, 0x9b05688cUL, 0x1f83d9abUL, 0x5be0cd19UL };

inline uint32_t right_rotate(uint32_t a, uint32_t b) { return (a >> b) | (a << (32 - b)); }

constexpr uint32_t k[] = 
{
	0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL, 0x3956c25bUL, 0x59f111f1UL, 0x923f82a4, 0xab1c5ed5UL,
	0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL, 0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7, 0xc19bf174UL,
	0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL, 0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dc, 0x76f988daUL,
	0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL, 0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351, 0x14292967UL,
	0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL, 0x650a7354UL, 0x766a0abbUL, 0x81c2c92e, 0x92722c85UL,
	0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL, 0xd192e819UL, 0xd6990624UL, 0xf40e3585, 0x106aa070UL,
	0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL, 0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4f, 0x682e6ff3UL,
	0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL, 0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7, 0xc67178f2UL
};

CMDA_SHA256::CMDA_SHA256()
	: p_val(c_sha256initvar, 8)
{
	p_salt = nullptr;
	p_saltlen = 0;

	buflen = 0;
	totbytes = 0;
}

CMDA_SHA256::~CMDA_SHA256()
{
	if (p_salt != nullptr)
	{
		delete[] p_salt;
		p_salt = nullptr;
		p_saltlen = 0;
	}
}

void CMDA_SHA256::init()
{
	p_val.init(c_sha256initvar, 8);

	if (p_salt != nullptr)
	{
		delete[] p_salt;
		p_salt = nullptr;
		p_saltlen = 0;
	}

	buflen = 0;
	totbytes = 0;
}

void CMDA_SHA256::set_salt(const uint8_t * salt, const uint32_t len)
{
	if (p_salt != nullptr)
	{
		delete[] p_salt;
	}

	p_salt = new uint8_t[len];
	memcpy_s(p_salt, sizeof(uint8_t)*len, salt, sizeof(uint8_t)*len);
	p_saltlen = len;
}

bool CMDA_SHA256::update(const uint8_t * src, const uint64_t len)
{
	uint64_t cnt = 0;
	while (cnt < len)
	{
		uint64_t bufleft = (len - cnt > 64 - buflen) ? (64 - buflen) : (len - cnt);
		memcpy_s(&buffer[buflen], (rsize_t)bufleft * sizeof(uint8_t), src + cnt, (rsize_t)bufleft * sizeof(uint8_t));
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

bool CMDA_SHA256::finish(_MDAVALUE & dst)
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
		buffer[buflen + i] = (totbits >> (56 - i * 8)) & 0xff;
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

void CMDA_SHA256::transform()
{
	uint32_t word[64];
	for (size_t j = 0; j < 16; ++j)
	{
		word[j] = buffer[4 * j + 0] << 24 | buffer[4 * j + 1] << 16 | buffer[4 * j + 2] << 8 | buffer[4 * j + 3];
	}
	for (size_t j = 16; j < 64; ++j)
	{
		uint32_t s0 = right_rotate(word[j - 15], 7) ^ right_rotate(word[j - 15], 18) ^ (word[j - 15] >> 3);
		uint32_t s1 = right_rotate(word[j - 2], 17) ^ right_rotate(word[j - 2], 19) ^ (word[j - 2] >> 10);
		word[j] = word[j - 16] + s0 + word[j - 7] + s1;
	}

	uint32_t a = p_val.pval[0], b = p_val.pval[1], c = p_val.pval[2], d = p_val.pval[3], e = p_val.pval[4], f = p_val.pval[5], g = p_val.pval[6], h = p_val.pval[7];

	for (int i = 0; i < 64; ++i)
	{
		uint32_t s0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22);
		uint32_t maj = (a&b) ^ (a&c) ^ (b&c);
		uint32_t t2 = s0 + maj;
		uint32_t s1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25);
		uint32_t ch = (e&f) ^ ((~e)&g);
		uint32_t t1 = h + s1 + ch + k[i] + word[i];
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	p_val.pval[0] += a;
	p_val.pval[1] += b;
	p_val.pval[2] += c;
	p_val.pval[3] += d;
	p_val.pval[4] += e;
	p_val.pval[5] += f;
	p_val.pval[6] += g;
	p_val.pval[7] += h;
}

void CreateSHA256(CMDA_Base*& pbase)
{
	pbase = reinterpret_cast<CMDA_Base*>(new CMDA_SHA256());
}

void ReleaseSHA256(CMDA_Base*& pbase)
{
	if (pbase != nullptr)
	{
		CMDA_SHA256* psha256 = reinterpret_cast<CMDA_SHA256*>(pbase);
		delete psha256;
		pbase = nullptr;
	}
}

void CalcSHA256(const uint8_t* src, const uint64_t len, _MDAVALUE& val, const uint8_t* salt, const uint32_t saltlen)
{
	CMDA_SHA256* psha256 = new CMDA_SHA256();
	psha256->init();
	if (salt != nullptr && saltlen != 0)
	{
		psha256->set_salt(salt, saltlen);
	}
	if (src != nullptr && len != 0)
	{
		psha256->update(src, len);
	}
	psha256->finish(val);
	delete psha256;
}
