#include "pch.h"

#include <cstdio>
#include <sys/stat.h>
#include <io.h>
#include <string>
#include <ctime>
#include <set>

#include "../../FileWithRingBuffer/FileWithRingBuffer/FileMap.h"

#include "MDAdefines.h"

void PreProcessVal(_MDAVALUE& val, enum_digest& digest)
{
	if (val.len == 17)
	{
		if (val.pval[16] % c_md5 == 0)
		{
			digest = enum_digest::enum_digest_md5;
		}
		else if (val.pval[16] % c_sha1 == 0)
		{
			digest = enum_digest::enum_digest_sha1;
		}
		else if (val.pval[16] % c_sha2_256 == 0)
		{
			digest = enum_digest::enum_digest_sha2_256;
		}
	}
	else
	{
		srand(static_cast<unsigned int>(time(nullptr)));
		val.init(17);
		switch (rand() % 3)
		{
		case 0:
			val.pval[16] = (rand() / c_md5) * c_md5;
			digest = enum_digest::enum_digest_md5;
			break;
		case 1:
			val.pval[16] = (rand() / c_sha1) * c_sha1;
			digest = enum_digest::enum_digest_sha1;
			break;
		case 2:
			val.pval[16] = (rand() / c_sha2_256) * c_sha2_256;
			digest = enum_digest::enum_digest_sha2_256;
			break;
		}
	}
}

void PostProcessVal(enum_digest digest, _MDAVALUE& val)
{
	srand(static_cast<unsigned int>(time(nullptr)));
	if (val.len < 17)
	{
		_MDAVALUE temp(val.pval, val.len);
		val.init(17);
		memcpy_s(val.pval, sizeof(uint32_t) * 17, temp.pval, sizeof(uint32_t)*temp.len);
		for (int i = temp.len; i < 16; ++i)
		{
			val.pval[i] = rand() % 268435456 + 268435456;
		}

		int r = rand() * 65535;
		switch (digest)
		{
		case enum_digest::enum_digest_md5:
			val.pval[16] = (r / c_md5) * c_md5;
			break;
		case enum_digest::enum_digest_sha1:
			val.pval[16] = (r / c_sha1) * c_sha1;
			break;
		case enum_digest::enum_digest_sha2_256:
			val.pval[16] = (r / c_sha2_256) * c_sha2_256;
			break;
		}
	}
}

void FindFiles(const char* path, std::set<std::string>& files)
{
	std::string format = path;
	format.append("\\*");
	struct _finddata_t info;
	intptr_t hfile;
	hfile = _findfirst(format.c_str(), &info);
	if (hfile != -1)
	{
		do {
			if (info.attrib&_A_SUBDIR)
			{
				if (strcmp(info.name, ".") && strcmp(info.name, ".."))
				{
					std::string folder = path;
					folder.append("\\");
					folder.append(info.name);
					FindFiles(folder.c_str(),files);
				}
			}
			else
			{
				std::string fullpath = path;
				fullpath.append("\\");
				fullpath.append(info.name);
				files.insert(fullpath);
			}
		} while (_findnext(hfile, &info) == 0);

		_findclose(hfile);
	}
}

bool PathDigest(const char* path, _MDAVALUE& val, const uint8_t * salt, const uint32_t saltlen)
{
	DWORDLONG a = GetTickCount64();

	enum_digest digest;
	PreProcessVal(val, digest);

	std::set<std::string> files;
	files.clear();

	FindFiles(path, files);

	CMDA_Base* base = nullptr;
	switch (digest)
	{
	case enum_digest::enum_digest_md5: CreateMD5(base); break;
	case enum_digest::enum_digest_sha1: CreateSHA1(base); break;
	case enum_digest::enum_digest_sha2_256: CreateSHA256(base); break;
	}

	for (auto it = files.begin(); it != files.end(); ++it)
	{
		FileMap::FileMap* filemap = new FileMap::FileMap;
		if (filemap->Open(it->c_str(), 0))
		{
			uint8_t* buf = new uint8_t[1024 * 1024 * 16];
			while (1)
			{
				DWORD dwrd = 1024 * 1024 * 16;
				if(filemap->Read(buf, dwrd))
				{
					base->update(buf, dwrd);
				}
				else
				{
					//printf("break\n");
					break;
				}
			}
			filemap->Close();
			delete buf;
		}
		delete filemap;
	}

	base->finish(val);

	switch (digest)
	{
	case enum_digest::enum_digest_md5: ReleaseMD5(base); break;
	case enum_digest::enum_digest_sha1: ReleaseSHA1(base); break;
	case enum_digest::enum_digest_sha2_256: ReleaseSHA256(base); break;
	}
	

	PostProcessVal(digest, val);

	DWORDLONG b = GetTickCount64();
	printf("cost %llu\n", b - a);
	return true;
}

bool FileDigest(const char* path, _MDAVALUE& val, const uint8_t * salt, const uint32_t saltlen)
{
	DWORDLONG a = GetTickCount64();

	enum_digest digest;
	PreProcessVal(val, digest);

	CMDA_Base* base = nullptr;
	switch (digest)
	{
	case enum_digest::enum_digest_md5: CreateMD5(base); break;
	case enum_digest::enum_digest_sha1: CreateSHA1(base); break;
	case enum_digest::enum_digest_sha2_256: CreateSHA256(base); break;
	}

	FileMap::FileMap* filemap = new FileMap::FileMap;
	if (filemap->Open(path, 0))
	{
		uint8_t* buf = new uint8_t[1024 * 1024 * 16];
		while (1)
		{
			DWORD dwrd = 1024 * 1024 * 16;
			if(filemap->Read(buf, dwrd))
			{
				base->update(buf, dwrd);
			}
			else
			{
				break;
			}
		}
		filemap->Close();
		delete buf;
	}
	delete filemap;
	base->finish(val);

	switch (digest)
	{
	case enum_digest::enum_digest_md5: ReleaseMD5(base); break;
	case enum_digest::enum_digest_sha1: ReleaseSHA1(base); break;
	case enum_digest::enum_digest_sha2_256: ReleaseSHA256(base); break;
	}

	PostProcessVal(digest, val);

	DWORDLONG b = GetTickCount64();
	printf("cost %llu\n", b - a);
	return true;
}

bool Digest(const uint8_t* src, const uint64_t len, _MDAVALUE& val, const uint8_t* salt, const uint32_t saltlen)
{
	DWORDLONG a = GetTickCount64();

	enum_digest digest;
	PreProcessVal(val, digest);

	switch (digest)
	{
	case enum_digest::enum_digest_md5:
		CalcMD5(src, len, val, salt, saltlen);
		break;
	case enum_digest::enum_digest_sha1:
		CalcSHA1(src, len, val, salt, saltlen);
		break;
	case enum_digest::enum_digest_sha2_256:
		CalcSHA256(src, len, val, salt, saltlen);
		break;
	default: return false;
	}

	PostProcessVal(digest, val);

	DWORDLONG b = GetTickCount64();
	printf("cost %llu\n", b - a);
	return true;
}