#include "pch.h"
#include "CMDA_SHA1.h"

CMDA_SHA1::CMDA_SHA1()
	: p_val(c_sha1initvar, 5)
{
	p_salt = nullptr;
	p_saltlen = 0;

	buflen = 0;
	totbytes = 0;
}

CMDA_SHA1::~CMDA_SHA1()
{
	if (p_salt != nullptr)
	{
		delete[] p_salt;
		p_salt = nullptr;
		p_saltlen = 0;
	}
}

void CMDA_SHA1::init()
{
	p_val.init(c_sha1initvar, 5);

	if (p_salt != nullptr)
	{
		delete[] p_salt;
		p_salt = nullptr;
		p_saltlen = 0;
	}

	buflen = 0;
	totbytes = 0;
}

void CMDA_SHA1::set_salt(const uint8_t * salt, const uint32_t len)
{
	if (p_salt != nullptr)
	{
		delete[] p_salt;
	}

	p_salt = new uint8_t[len];
	memcpy_s(p_salt, sizeof(uint8_t)*len, salt, sizeof(uint8_t)*len);
	p_saltlen = len;
}

bool CMDA_SHA1::update(const uint8_t * src, const uint64_t len)
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

bool CMDA_SHA1::finish(_MDAVALUE & dst)
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

void CMDA_SHA1::transform()
{
	uint32_t word[80];
	for (size_t j = 0; j < 16; ++j)
	{
		word[j] = buffer[4 * j + 0] << 24 | buffer[4 * j + 1] << 16 | buffer[4 * j + 2] << 8 | buffer[4 * j + 3];
	}
	for (size_t j = 16; j < 80; ++j)
	{
		word[j] = left_rotate(word[j - 3] ^ word[j - 8] ^ word[j - 14] ^ word[j - 16], 1);
	}

	uint32_t a = p_val.pval[0], b = p_val.pval[1], c = p_val.pval[2], d = p_val.pval[3], e = p_val.pval[4];

	for (int i = 0; i < 80; ++i)
	{
		uint32_t f, k;
		if (i < 20)
		{
			ROUND1(a, b, c, d, f, k);
		}
		else if (i < 40)
		{
			ROUND2(a, b, c, d, f, k);
		}
		else if (i < 60)
		{
			ROUND3(a, b, c, d, f, k);
		}
		else
		{
			ROUND4(a, b, c, d, f, k);
		}

		uint32_t tmp = left_rotate(a, 5) + f + e + k + word[i];
		e = d;
		d = c;
		c = left_rotate(b, 30);
		b = a;
		a = tmp;
	}

	p_val.pval[0] += a;
	p_val.pval[1] += b;
	p_val.pval[2] += c;
	p_val.pval[3] += d;
	p_val.pval[4] += e;
}

void CreateSHA1(CMDA_Base*& pbase)
{
	pbase = reinterpret_cast<CMDA_Base*>(new CMDA_SHA1());
}

void ReleaseSHA1(CMDA_Base*& pbase)
{
	if (pbase != nullptr)
	{
		CMDA_SHA1* psha1 = reinterpret_cast<CMDA_SHA1*>(pbase);
		delete psha1;
		pbase = nullptr;
	}
}

void CalcSHA1(const uint8_t* src, const uint64_t len, _MDAVALUE& val, const uint8_t* salt, const uint32_t saltlen)
{
	CMDA_SHA1* psha1 = new CMDA_SHA1();
	psha1->init();
	if (salt != nullptr && saltlen != 0)
	{
		psha1->set_salt(salt, saltlen);
	}
	if (src != nullptr && len != 0)
	{
		psha1->update(src, len);
	}
	psha1->finish(val);
	delete psha1;
}

