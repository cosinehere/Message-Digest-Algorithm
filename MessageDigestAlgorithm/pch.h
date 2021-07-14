#ifndef PCH_H
#define PCH_H

#if defined(_MSC_VER)	// MSVC

#if _MSC_VER < 1400	// stdint.h

typedef char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef __int64 int64_t;
typedef unsigned __int64 uint64_t;

#else

#include <cstdint>

#endif

#if _MSC_VER < 1900 // C++11

#define constexpr const
#define nullptr NULL
#define override

#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#elif defined(__GNUC__)

#include <cstdio>
#include <cstdlib>
#include <cstddef>
#include <cstring>

#endif // defined(_MSC_VER)

#define _MDADLL_EXPORT_

#endif //PCH_H
