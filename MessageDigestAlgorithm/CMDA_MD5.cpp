#include "pch.h"
#include "CMDA_MD5.h"

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

void CMDA_MD5::set_salt(const uint8_t* salt, const uint32_t len)
{
	if (p_salt != nullptr)
	{
		delete[] p_salt;
	}
	
	p_salt = new uint8_t[len];
	memcpy_s(p_salt, sizeof(uint8_t)*len, salt, sizeof(uint8_t)*len);
	p_saltlen = len;
}

bool CMDA_MD5::update(const uint8_t* src, const uint64_t len)
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
	uint32_t a = p_val.pval[0], b = p_val.pval[1], c = p_val.pval[2], d = p_val.pval[3];
	uint32_t* pbuf = reinterpret_cast<uint32_t*>(buffer);

	ROUND1(a, b, c, d, pbuf);
	ROUND2(a, b, c, d, pbuf);
	ROUND3(a, b, c, d, pbuf);
	ROUND4(a, b, c, d, pbuf);

	p_val.pval[0] += a;
	p_val.pval[1] += b;
	p_val.pval[2] += c;
	p_val.pval[3] += d;
}

void CreateMD5(CMDA_Base*& pbase)
{
	pbase = reinterpret_cast<CMDA_Base*>(new CMDA_MD5());
}

void ReleaseMD5(CMDA_Base*& pbase)
{
	if (pbase != nullptr)
	{
		CMDA_MD5* pmd5 = reinterpret_cast<CMDA_MD5*>(pbase);
		delete pmd5;
		pbase = nullptr;
	}
}

void CalcMD5(const uint8_t* src, const uint64_t len, _MDAVALUE& val, const uint8_t* salt, const uint32_t saltlen)
{
	CMDA_MD5* pmd5 = new CMDA_MD5();
	pmd5->init();
	if (salt != nullptr && saltlen != 0)
	{
		pmd5->set_salt(salt, saltlen);
	}
	if (src != nullptr && len != 0)
	{
		pmd5->update(src, len);
	}
	pmd5->finish(val);
	delete pmd5;
}
