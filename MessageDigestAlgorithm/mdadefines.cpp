#include "pch.h"

#include "mdadefines.h"
#include "CMDA_MD5.h"
#include "CMDA_SHA1.h"
#include "CMDA_SHA256.h"
#include "CMDA_SHA512.h"

inline void CreateMD5(CMDA_Base*& pbase)
{
	pbase = reinterpret_cast<CMDA_Base*>(new CMDA_MD5());
}

inline void ReleaseMD5(CMDA_Base*& pbase)
{
	if (pbase != nullptr)
	{
		CMDA_MD5* pmd5 = reinterpret_cast<CMDA_MD5*>(pbase);
		delete pmd5;
		pbase = nullptr;
	}
}

inline void CreateSHA1(CMDA_Base*& pbase)
{
	pbase = reinterpret_cast<CMDA_Base*>(new CMDA_SHA1());
}

inline void ReleaseSHA1(CMDA_Base*& pbase)
{
	if (pbase != nullptr)
	{
		CMDA_SHA1* psha1 = reinterpret_cast<CMDA_SHA1*>(pbase);
		delete psha1;
		pbase = nullptr;
	}
}

inline void CreateSHA256(CMDA_Base*& pbase)
{
	pbase = reinterpret_cast<CMDA_Base*>(new CMDA_SHA256());
}

inline void ReleaseSHA256(CMDA_Base*& pbase)
{
	if (pbase != nullptr)
	{
		CMDA_SHA256* psha256 = reinterpret_cast<CMDA_SHA256*>(pbase);
		delete psha256;
		pbase = nullptr;
	}
}

inline void CreateSHA512(CMDA_Base*& pbase)
{
	pbase = reinterpret_cast<CMDA_Base*>(new CMDA_SHA512());
}

inline void ReleaseSHA512(CMDA_Base*& pbase)
{
	if (pbase != nullptr)
	{
		CMDA_SHA512* psha512 = reinterpret_cast<CMDA_SHA512*>(pbase);
		delete psha512;
		pbase = nullptr;
	}
}

void CreateBase(enum_digest digest, CMDA_Base*& base)
{
	switch (digest)
	{
	case enum_digest_md5: CreateMD5(base); break;
	case enum_digest_sha1: CreateSHA1(base); break;
	case enum_digest_sha2_256: CreateSHA256(base); break;
	case enum_digest_sha2_512: CreateSHA512(base); break;
	}
}

void ReleaseBase(enum_digest digest, CMDA_Base*& base)
{
	switch (digest)
	{
	case enum_digest_md5: ReleaseMD5(base); break;
	case enum_digest_sha1: ReleaseSHA1(base); break;
	case enum_digest_sha2_256: ReleaseSHA256(base); break;
	case enum_digest_sha2_512: ReleaseSHA512(base); break;
	}
}

void CalcMD5(const uint8_t* src, const size_t len, _MDAVALUE& val, const uint8_t* salt, const size_t saltlen)
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

void CalcSHA1(const uint8_t* src, const size_t len, _MDAVALUE& val, const uint8_t* salt, const size_t saltlen)
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

void CalcSHA256(const uint8_t* src, const size_t len, _MDAVALUE& val, const uint8_t* salt, const size_t saltlen)
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

void CalcSHA512(const uint8_t* src, const size_t len, _MDAVALUE& val, const uint8_t* salt, const size_t saltlen)
{
	CMDA_SHA512* psha512 = new CMDA_SHA512();
	psha512->init();
	if (salt != nullptr && saltlen != 0)
	{
		psha512->set_salt(salt, saltlen);
	}
	if (src != nullptr && len != 0)
	{
		psha512->update(src, len);
	}
	psha512->finish(val);
	delete psha512;
}
