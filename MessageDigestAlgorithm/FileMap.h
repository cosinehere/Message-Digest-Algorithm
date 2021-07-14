#pragma once

#if !defined(_MSC_VER)
typedef unsigned int DWORD;
typedef unsigned long long DWORDLONG;
typedef void* HANDLE;
typedef void* LPVOID;
typedef const char* LPCTSTR;
#endif

namespace FileMap {

constexpr DWORD MAP_SIZE = 0x20000000UL;
constexpr DWORDLONG  OFFSET_MASK_FILE = 0xffffffffe0000000ULL;
constexpr DWORDLONG  OFFSET_MASK_MAP = 0x000000001fffffffULL;

class FileMap
{
private:
	bool m_bOpen;
	HANDLE m_hFile;
	HANDLE m_hMap;
	LPVOID m_pMap;

	union {
		DWORDLONG quad;
		struct {
			DWORD low;
			DWORD high;
		};
	}m_filesize, m_fileoffset;
	DWORD m_mapsize;

public:
	FileMap();
	~FileMap();

	bool Open(LPCTSTR strFile);
	void Close();
	bool Remap();

	LPVOID GetBuffer() { return m_pMap; }
	DWORD GetLength() { return m_mapsize; }
};

} //namespace FileMap