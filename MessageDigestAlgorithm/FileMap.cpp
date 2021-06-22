#include "pch.h"

#include "FileMap.h"

namespace FileMap {

FileMap::FileMap()
{
	m_bOpen = false;
	m_hFile = nullptr;
	m_hMap = nullptr;
	m_pMap = nullptr;

	m_filesize.quad = 0;
	m_fileoffset.quad = 0;
	m_mapsize = 0;
}

FileMap::~FileMap()
{
	Close();
}

bool FileMap::Open(LPCTSTR strFile)
{
	if (m_bOpen == true)
	{
		return false;
	}

	m_hFile = CreateFile(strFile, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (m_hFile == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	m_filesize.low = GetFileSize(m_hFile, &m_filesize.high);
	if (m_filesize.quad == 0 || m_filesize.low == INVALID_FILE_SIZE)
	{
		CloseHandle(m_hFile);
		return false;
	}

	m_hMap = CreateFileMapping(m_hFile, NULL, PAGE_READONLY, 0, 0, nullptr);
	if (m_hMap == nullptr)
	{
		CloseHandle(m_hFile);
		return false;
	}

	m_fileoffset.quad = 0;
	m_mapsize = 0;
	m_pMap = nullptr;
	m_bOpen = true;

	return true;
}

void FileMap::Close()
{
	if (m_bOpen == false)
	{
		return;
	}
	UnmapViewOfFile(m_pMap);
	CloseHandle(m_hMap);
	CloseHandle(m_hFile);

	m_bOpen = false;
}

bool FileMap::Remap()
{
	if (m_bOpen == false)
	{
		return false;
	}

	if (m_pMap != nullptr)
	{
		UnmapViewOfFile(m_pMap);
	}

	m_fileoffset.quad += m_mapsize;

	m_mapsize = ((m_filesize.quad - m_fileoffset.quad) > MAP_SIZE) ? MAP_SIZE : static_cast<DWORD>(m_filesize.quad - m_fileoffset.quad);
	m_pMap = MapViewOfFile(m_hMap, FILE_MAP_READ, m_fileoffset.high, m_fileoffset.low, m_mapsize);
	if (m_pMap == nullptr)
	{
		return false;
	}

	return true;
}

};
