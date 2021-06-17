#pragma once

#ifdef _MDADLL_EXPORT_
#define MDA_EXT _declspec(dllexport)
#else
#define MDA_EXT _declspec(dllimport)
#endif

#include <stdint.h>
#ifndef _STDINT
typedef signed char        int8_t;
typedef short              int16_t;
typedef int                int32_t;
typedef long long          int64_t;
typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;
#endif // ifndef _STDINT

struct _MDAVALUE
{
	uint32_t* pval;
	uint32_t len;

	_MDAVALUE()
	{
		pval = nullptr;
		len = 0;
	}

	_MDAVALUE(const uint32_t l)
	{
		if (l == 0)
		{
			pval = nullptr;
			len = 0;
		}
		else
		{
			pval = new uint32_t[l];
			memset(pval, 0, sizeof(uint32_t)*l);
			len = l;
		}
	}

	_MDAVALUE(const uint32_t* val, const uint32_t l)
	{
		if (val == nullptr || l == 0)
		{
			pval = nullptr;
			len = 0;
		}
		else
		{
			pval = new uint32_t[l];
			memcpy_s(pval, sizeof(uint32_t)*l, val, sizeof(uint32_t)*l);
			len = l;
		}
	}

	~_MDAVALUE()
	{
		clear();
	}

	void clear()
	{
		if (pval != nullptr)
		{
			delete[] pval;
			pval = nullptr;
			len = 0;
		}
	}

	void init(const uint32_t l)
	{
		clear();

		if (l != 0)
		{
			pval = new uint32_t[l];
			memset(pval, 0, sizeof(uint32_t)*l);
			len = l;
		}
	}

	void init(const uint32_t* val, const uint32_t l)
	{
		clear();

		if (val != nullptr && l != 0)
		{
			pval = new uint32_t[l];
			len = l;
			memcpy_s(pval, sizeof(uint32_t)*l, val, sizeof(uint32_t)*l);
		}
	}

	_MDAVALUE& operator=(const _MDAVALUE& o)
	{
		init(o.pval, o.len);
		return *this;
	}

	bool operator==(const _MDAVALUE& o) const
	{
		if (len != o.len)
		{
			return false;
		}

		return (memcmp(pval, o.pval, sizeof(uint32_t)*len)==0);
	}
};

class MDA_EXT CMDA_Base
{
public:
	CMDA_Base() = default;
	virtual ~CMDA_Base() = default;
	CMDA_Base(const CMDA_Base&) = delete;
	CMDA_Base& operator=(const CMDA_Base&) = delete;
	CMDA_Base(const CMDA_Base&&) = delete;
	CMDA_Base& operator=(const CMDA_Base&&) = delete;

	virtual void init() = 0;
	virtual void set_salt(const uint8_t* salt, const uint32_t len) = 0;
	virtual bool update(const uint8_t* src, const uint64_t len) = 0;
	virtual bool finish(_MDAVALUE& dst) = 0;
};

extern "C" MDA_EXT void CreateMD5(CMDA_Base*& pbase);
extern "C" MDA_EXT void ReleaseMD5(CMDA_Base*& pbase);
extern "C" MDA_EXT void CalcMD5(const uint8_t* src, const uint64_t len, _MDAVALUE& val, const uint8_t* salt, const uint32_t saltlen);

extern "C" MDA_EXT void CreateSHA1(CMDA_Base*& pbase);
extern "C" MDA_EXT void ReleaseSHA1(CMDA_Base*& pbase);
extern "C" MDA_EXT void CalcSHA1(const uint8_t* src, const uint64_t len, _MDAVALUE& val, const uint8_t* salt, const uint32_t saltlen);

extern "C" MDA_EXT void CreateSHA256(CMDA_Base*& pbase);
extern "C" MDA_EXT void ReleaseSHA256(CMDA_Base*& pbase);
extern "C" MDA_EXT void CalcSHA256(const uint8_t* src, const uint64_t len, _MDAVALUE& val, const uint8_t* salt, const uint32_t saltlen);

