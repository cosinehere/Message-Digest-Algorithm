#pragma once

#ifdef _MDADLL_EXPORT_
	#define MDA_EXT _declspec(dllexport)
#else
	#define MDA_EXT _declspec(dllimport)
#endif

#include <stdint.h>
#ifndef _STDINT
#define _STDINT
typedef char				int8_t;
typedef short				int16_t;
typedef int					int32_t;
typedef __int64				int64_t;
typedef unsigned char		uint8_t;
typedef unsigned short		uint16_t;
typedef unsigned int		uint32_t;
typedef unsigned __int64	uint64_t;
#endif // ifndef _STDINT

#if (!defined(_MSC_VER) && __cplusplus < 201103L) || (defined(_MSC_VER) && _MSC_VER < 1900)   // C++11 is not supported.
	#define nullptr  NULL
	#define override
#endif

struct _MDAVALUE
{
	uint32_t val[17];
	size_t len;

	_MDAVALUE()
	{
		memset(val, 0, sizeof(val));
		len = 0;
	}

	_MDAVALUE(const uint32_t* v, const size_t l)
	{
		if (v == nullptr || l == 0)
		{
			len = 0;
		}
		else
		{
			len = (l > 17) ? 17 : l;
			memcpy_s(val, sizeof(uint32_t)*len, v, sizeof(uint32_t)*len);
		}
	}

	void init(const uint32_t* v, const size_t l)
	{
		if (v != nullptr && l != 0)
		{
			len = (l > 17) ? 17 : l;
			memcpy_s(val, sizeof(uint32_t)*len, v, sizeof(uint32_t)*len);
		}
	}

	_MDAVALUE& operator=(const _MDAVALUE& o)
	{
		init(o.val, o.len);
		return *this;
	}

	bool operator==(const _MDAVALUE& o) const
	{
		if (len != o.len)
		{
			return false;
		}

		return (memcmp(val, o.val, sizeof(uint32_t)*len)==0);
	}
};

class CMDA_Base
{
public:
	virtual void init() = 0;
	virtual void set_salt(const uint8_t* salt, const size_t len) = 0;
	virtual bool update(const uint8_t* src, const size_t len) = 0;
	virtual bool finish(_MDAVALUE& dst) = 0;

	virtual ~CMDA_Base() = default;
};

enum enum_digest
{
	enum_digest_md5 = 0,
	enum_digest_sha1,
	enum_digest_sha2_256,
	enum_digest_sha2_512,
	//enum_digest_sha3

	enum_digest_num
};

enum enum_module
{
	enum_all = 0
};

constexpr char c_strpath_all[] = ".\\";

extern "C" MDA_EXT bool Digest(const uint8_t* src, const size_t len, _MDAVALUE& val, const uint8_t* salt, const size_t saltlen);
extern "C" MDA_EXT bool DigestSel(enum_digest digest, const uint8_t* src, const size_t len, _MDAVALUE& val, const uint8_t* salt, const size_t saltlen);

extern "C" MDA_EXT bool FileDigest(const char* path, _MDAVALUE& val);

extern "C" MDA_EXT bool PathDigest(const char* path, _MDAVALUE& val, bool recursive);
extern "C" MDA_EXT bool ModuleDigest(enum_module module, _MDAVALUE& val);

template <typename T>
inline T l_rot(T a, T b)
{
	return (a << b) | (a >> (sizeof(T) * 8 - b));
}

template <typename T>
inline T r_rot(T a, T b)
{
	return (a >> b) | (a << (sizeof(T) * 8 - b));
}

constexpr uint32_t c_digestmod[] = { 65537,65539,65543,65551 };

void PreProcessVal(_MDAVALUE& val, enum_digest& digest);
void PostProcessVal(enum_digest digest, _MDAVALUE& val);

void CreateMD5(CMDA_Base*& pbase);
void ReleaseMD5(CMDA_Base*& pbase);
void CalcMD5(const uint8_t* src, const size_t len, _MDAVALUE& val, const uint8_t* salt, const size_t saltlen);

void CreateSHA1(CMDA_Base*& pbase);
void ReleaseSHA1(CMDA_Base*& pbase);
void CalcSHA1(const uint8_t* src, const size_t len, _MDAVALUE& val, const uint8_t* salt, const size_t saltlen);

void CreateSHA256(CMDA_Base*& pbase);
void ReleaseSHA256(CMDA_Base*& pbase);
void CalcSHA256(const uint8_t* src, const size_t len, _MDAVALUE& val, const uint8_t* salt, const size_t saltlen);

void CreateSHA512(CMDA_Base*& pbase);
void ReleaseSHA512(CMDA_Base*& pbase);
void CalcSHA512(const uint8_t* src, const size_t len, _MDAVALUE& val, const uint8_t* salt, const size_t saltlen);
