#pragma once

#if defined(_MSC_VER)
#ifdef _MDALIB_EXPORT_
#define MDAEXT
#elif defined(_MDADLL_EXPORT_)
#define MDAEXT __declspec(dllexport)
#else
#define MDAEXT __declspec(dllimport)
#endif

#define NOVTABLE __declspec(novtable)

#else
#ifdef _MDALIB_EXPORT_
#define MDAEXT
#elif defined(_MDADLL_EXPORT_)
#define MDAEXT __attribute__((visibility("default")))
#else
#define MDAEXT
#endif

#define NOVTABLE

#endif // defined(_MSC_VER)

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
			memcpy(val, v, sizeof(uint32_t)*len);
		}
	}

	void init(const uint32_t* v, const size_t l)
	{
		if (v != nullptr && l != 0)
		{
			len = (l > 17) ? 17 : l;
			memcpy(val, v, sizeof(uint32_t)*len);
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

		return (memcmp(val, o.val, sizeof(uint32_t)*len) == 0);
	}
};

class NOVTABLE CMDA_Base
{
public:
	virtual void init() = 0;
	virtual void set_salt(const uint8_t* salt, const size_t len) = 0;
	virtual bool update(const uint8_t* src, const size_t len) = 0;
	virtual bool finish(_MDAVALUE& dst) = 0;

	virtual ~CMDA_Base() {};
};

enum enum_digest
{
	enum_digest_begin = 0,

	enum_digest_md5 = enum_digest_begin,
	enum_digest_sha1,
	enum_digest_sha2_256,
	enum_digest_sha2_512,
	//enum_digest_sha3

	enum_digest_end,
	enum_digest_num = enum_digest_end - enum_digest_begin
};

MDAEXT void CreateBase(enum_digest digest, CMDA_Base*& base);

MDAEXT void ReleaseBase(enum_digest digest, CMDA_Base*& base);

MDAEXT void CalcMD5(const uint8_t* src, const size_t len, _MDAVALUE& val, const uint8_t* salt, const size_t saltlen);

MDAEXT void CalcSHA1(const uint8_t* src, const size_t len, _MDAVALUE& val, const uint8_t* salt, const size_t saltlen);

MDAEXT void CalcSHA256(const uint8_t* src, const size_t len, _MDAVALUE& val, const uint8_t* salt, const size_t saltlen);

MDAEXT void CalcSHA512(const uint8_t* src, const size_t len, _MDAVALUE& val, const uint8_t* salt, const size_t saltlen);
