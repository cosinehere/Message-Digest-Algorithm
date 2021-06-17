#include "pch.h"
#include "CMDA_SHA256.h"

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

extern "C" MDA_EXT void CreateSHA256(CMDA_Base*& pbase)
{
	pbase = reinterpret_cast<CMDA_Base*>(new CMDA_SHA256());
}

extern "C" MDA_EXT void ReleaseSHA256(CMDA_Base*& pbase)
{
	if (pbase != nullptr)
	{
		CMDA_SHA256* psha256 = reinterpret_cast<CMDA_SHA256*>(pbase);
		delete psha256;
		pbase = nullptr;;
	}
}

extern "C" MDA_EXT void CalcSHA256(const uint8_t* src, const uint64_t len, _MDAVALUE& val, const uint8_t* salt, const uint32_t saltlen)
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
