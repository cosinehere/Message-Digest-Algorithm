#pragma once

#ifndef _MDADEFINES_H_
#define _MDADEFINES_H_

#include "mdatypes.h"

#define _MDADLL_

#if defined(_MSC_VER)

#ifdef _MDADLL_
#ifdef _MDA_EXPORT_
#define MDAEXT __declspec(dllexport)
#else
#define MDAEXT __declspec(dllimport)
#endif  // _MDA_EXPORT_
#else
#define MDAEXT
#endif  // _MDADLL_

#else

#ifdef _MDADLL_
#ifdef _MDA_EXPORT_
#define MDAEXT __attribute__((visibility("default")))
#else
#define MDAEXT
#endif  // _MDA_EXPORT_
#else
#define MDAEXT
#endif  // _MDADLL_

#endif // defined(_MSC_VER)

/*! \enum enum_digest
*
*   Message Digest Algorithm enum type.
*/
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

#endif  // _MDADEFINES_H_
