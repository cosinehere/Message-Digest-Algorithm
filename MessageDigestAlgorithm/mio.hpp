#pragma once

#ifndef _MIO_HPP_
#define _MIO_HPP_

#include <cstddef>
#include <cstring>

#ifdef _MSC_VER
#if (_MSC_VER < 1400)
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
#endif	// _MSC_VER < 1400
#else
#include <cstdint>
#endif	// _MSC_VER

//////////////////////////////////////////////////////////////////////////
// system header
//////////////////////////////////////////////////////////////////////////
#ifdef _WIN32	// Windows
#ifndef _AFX	// without MFC
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif	// WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif	// _AFX
#else	// Unix
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#endif	// _WIN32

//////////////////////////////////////////////////////////////////////////
// typedef
//////////////////////////////////////////////////////////////////////////
#ifdef _WIN32	// Windows
typedef HANDLE HMIO;
#ifndef invalid_handle
#define invalid_handle INVALID_HANDLE_VALUE
#endif	// invalid_handle
#else	// Unix
#define invalid_handle -1
typedef int HMIO;
#endif	// _WIN32

#if !defined(NAMESPACE_BEGIN)  && !defined(NAMESPACE_END)
#define NAMESPACE_BEGIN(name) namespace name {
#define NAMESPACE_END }
#endif	// !defined(NAMESPACE_BEGIN)  && !defined(NAMESPACE_END)

//////////////////////////////////////////////////////////////////////////
// C++11 support
//////////////////////////////////////////////////////////////////////////
#if __cplusplus <= 199711L && \
	(!defined(_MSC_VER) || _MSC_VER < 1900) && \
	(!defined(__GNUC__) || \
	(__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__ < 40603))
#ifndef CXX11_NOT_SUPPORT
#define CXX11_NOT_SUPPORT
#endif	// CXX11_NOT_SUPPORT
#endif	// __cplusplus<=199711L

#ifdef CXX11_NOT_SUPPORT
#define nullptr NULL
#define constexpr const
#define noexcept throw()
#define override
#endif	// CXX11_NOT_SUPPORT

NAMESPACE_BEGIN(mio)

// read/write mode
enum enum_mio_mode {
	enum_mode_read = 0,
	enum_mode_write
};

template<enum_mio_mode Emode>
class mio
{
private:
	HMIO p_file;

	bool path_empty(const char* path) { return !path || (*path == '\0'); }

public:
	mio();
	~mio();
#ifndef CXX11_NOT_SUPPORT
	mio(const mio&) = delete;
	mio(const mio&&) = delete;
	mio& operator=(const mio&) = delete;
	mio& operator=(const mio&&) = delete;
#endif	// CXX11_NOT_SUPPORT

	bool is_open() noexcept { return p_file != invalid_handle; }

	bool open_file(const char* path);
	void close_file();

	size_t file_size();

	size_t read_file(void* buffer, size_t readnum);
	size_t write_file(const void* buffer, size_t writenum);
};

template<enum_mio_mode Emode>
mio<Emode>::mio()
{
	p_file = invalid_handle;
}

template<enum_mio_mode Emode>
mio<Emode>::~mio()
{
	if (is_open())
	{
		close_file();
	}
}

template<enum_mio_mode Emode>
bool mio<Emode>::open_file(const char* path)
{
	if (path_empty(path))
	{
		return false;
	}

	HMIO handle = invalid_handle;
#ifdef _WIN32
	handle = CreateFile(path,
		(Emode == enum_mode_read) ? GENERIC_READ : GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		0,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		0);
#else
	handle = open(path,
		(Emode == enum_mode_read) ? O_RDONLY : O_RDWR);
#endif	// _WIN32

	p_file = handle;
	return handle != invalid_handle;
}

template<enum_mio_mode Emode>
void mio<Emode>::close_file()
{
	if (!is_open())
	{
		return;
	}

#ifdef _WIN32
	CloseHandle(p_file);
#else
	close(p_file);
#endif	// _WIN32

	p_file = invalid_handle;
}

template<enum_mio_mode Emode>
size_t mio<Emode>::file_size()
{
	if (!is_open())
	{
		return 0;
	}

#ifdef _WIN32
	LARGE_INTEGER size;
	if (GetFileSizeEx(p_file, &size) == FALSE)
	{
		return 0;
	}
	return static_cast<size_t>(size.QuadPart);
#else
	struct stat st;
	if (fstat(p_file, &st) == -1)
	{
		return 0;
	}
	return static_cast<size_t>(st.st_size);
#endif
}

template<enum_mio_mode Emode>
size_t mio<Emode>::read_file(void* buffer, size_t readnum)
{
	if (!is_open())
	{
		return 0;
	}

	if (Emode != enum_mode_read)
	{
		return 0;
	}

#ifdef _WIN32
	DWORD dwRead = 0;
	if (!ReadFile(p_file, buffer, readnum, &dwRead, nullptr))
	{
		return 0;
	}
	return dwRead;
#else
	return read(p_file, buffer, readnum);
#endif	// _WIN32
}

template<enum_mio_mode Emode>
size_t mio<Emode>::write_file(const void* buffer, size_t writenum)
{
	if (!is_open())
	{
		return 0;
	}

	if (Emode != enum_mode_write)
	{
		return 0;
	}

#ifdef _WIN32
	DWORD dwWrite = 0;
	if (!WriteFile(p_file, buffer, writenum, &dwWrite, nullptr))
	{
		return 0;
	}
	return dwWrite;
#else
	return write(p_file, buffer, writenum);
#endif	// _WIN32
}

NAMESPACE_END

#endif	// _MIO_HPP_
