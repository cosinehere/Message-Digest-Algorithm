#include "pch.h"
#include "CMDA_SHA256.h"

#include "mdatemplates.h"

#define RROT(a,b) r_rot<uint32_t>(a,b)

constexpr uint32_t c_sha256initvar[] =
{ 0x6a09e667ul, 0xbb67ae85ul, 0x3c6ef372ul, 0xa54ff53aul, 0x510e527ful, 0x9b05688cul, 0x1f83d9abul, 0x5be0cd19ul };

constexpr uint32_t k[] =
{
	0x428a2f98ul, 0x71374491ul, 0xb5c0fbcful, 0xe9b5dba5ul, 0x3956c25bul, 0x59f111f1ul, 0x923f82a4, 0xab1c5ed5ul,
	0xd807aa98ul, 0x12835b01ul, 0x243185beul, 0x550c7dc3ul, 0x72be5d74ul, 0x80deb1feul, 0x9bdc06a7, 0xc19bf174ul,
	0xe49b69c1ul, 0xefbe4786ul, 0x0fc19dc6ul, 0x240ca1ccul, 0x2de92c6ful, 0x4a7484aaul, 0x5cb0a9dc, 0x76f988daul,
	0x983e5152ul, 0xa831c66dul, 0xb00327c8ul, 0xbf597fc7ul, 0xc6e00bf3ul, 0xd5a79147ul, 0x06ca6351, 0x14292967ul,
	0x27b70a85ul, 0x2e1b2138ul, 0x4d2c6dfcul, 0x53380d13ul, 0x650a7354ul, 0x766a0abbul, 0x81c2c92e, 0x92722c85ul,
	0xa2bfe8a1ul, 0xa81a664bul, 0xc24b8b70ul, 0xc76c51a3ul, 0xd192e819ul, 0xd6990624ul, 0xf40e3585, 0x106aa070ul,
	0x19a4c116ul, 0x1e376c08ul, 0x2748774cul, 0x34b0bcb5ul, 0x391c0cb3ul, 0x4ed8aa4aul, 0x5b9cca4f, 0x682e6ff3ul,
	0x748f82eeul, 0x78a5636ful, 0x84c87814ul, 0x8cc70208ul, 0x90befffaul, 0xa4506cebul, 0xbef9a3f7, 0xc67178f2ul
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

void CMDA_SHA256::set_salt(const uint8_t* salt, const size_t len)
{
	if (p_salt != nullptr)
	{
		delete[] p_salt;
	}

	p_salt = new uint8_t[len];
	memcpy(p_salt, salt, sizeof(uint8_t)*len);
	p_saltlen = len;
}

bool CMDA_SHA256::update(const uint8_t* src, const size_t len)
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
		uint32_t s0 = RROT(word[j - 15], 7) ^ RROT(word[j - 15], 18) ^ (word[j - 15] >> 3);
		uint32_t s1 = RROT(word[j - 2], 17) ^ RROT(word[j - 2], 19) ^ (word[j - 2] >> 10);
		word[j] = word[j - 16] + s0 + word[j - 7] + s1;
	}

	uint32_t a = p_val.val[0], b = p_val.val[1], c = p_val.val[2], d = p_val.val[3], e = p_val.val[4], f = p_val.val[5], g = p_val.val[6], h = p_val.val[7];

	for (int i = 0; i < 64; ++i)
	{
		uint32_t s0 = RROT(a, 2) ^ RROT(a, 13) ^ RROT(a, 22);
		uint32_t maj = (a&b) ^ (a&c) ^ (b&c);
		uint32_t t2 = s0 + maj;
		uint32_t s1 = RROT(e, 6) ^ RROT(e, 11) ^ RROT(e, 25);
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

	p_val.val[0] += a;
	p_val.val[1] += b;
	p_val.val[2] += c;
	p_val.val[3] += d;
	p_val.val[4] += e;
	p_val.val[5] += f;
	p_val.val[6] += g;
	p_val.val[7] += h;
}
