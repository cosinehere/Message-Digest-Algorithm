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
#endif // _MDA_EXPORT_
#else
#define MDAEXT
#endif // _MDADLL_

#else

#ifdef _MDADLL_
#ifdef _MDA_EXPORT_
#define MDAEXT __attribute__((visibility("default")))
#else
#define MDAEXT
#endif // _MDA_EXPORT_
#else
#define MDAEXT
#endif // _MDADLL_

#endif // defined(_MSC_VER)

namespace mda {

MDAEXT void CreateBase(enum_digest digest, CMDA_Base *&base);

MDAEXT void ReleaseBase(enum_digest digest, CMDA_Base *&base);

MDAEXT void CalcMD5(const uint8_t *src, const size_t len, _MDAVALUE &val,
                    const uint8_t *salt, const size_t saltlen);

MDAEXT void CalcSHA1(const uint8_t *src, const size_t len, _MDAVALUE &val,
                     const uint8_t *salt, const size_t saltlen);

MDAEXT void CalcSHA256(const uint8_t *src, const size_t len, _MDAVALUE &val,
                       const uint8_t *salt, const size_t saltlen);

MDAEXT void CalcSHA512(const uint8_t *src, const size_t len, _MDAVALUE &val,
                       const uint8_t *salt, const size_t saltlen);

} // namespace mda

#endif // _MDADEFINES_H_
