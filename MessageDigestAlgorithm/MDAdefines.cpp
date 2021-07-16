#include "pch.h"

#include <sys/stat.h>
#include <io.h>
#include <string>
#include <ctime>
#include <set>

//#include "FileMap.h"
#include "mio.hpp"

#include "MDAdefines.h"

void PreProcessVal(_MDAVALUE& val, enum_digest& digest)
{
	if (val.len == 17 && val.val[16])
	{
		if (val.val[16] % c_digestmod[enum_digest_md5] == 0)
		{
			digest = enum_digest_md5;
		}
		else if (val.val[16] % c_digestmod[enum_digest_sha1] == 0)
		{
			digest = enum_digest_sha1;
		}
		else if (val.val[16] % c_digestmod[enum_digest_sha2_256] == 0)
		{
			digest = enum_digest_sha2_256;
		}
		else //if (val.val[16] % c_digestmod[enum_digest_sha2_512] == 0)
		{
			digest = enum_digest_sha2_512;
		}
	}
	else
	{
		srand(static_cast<unsigned int>(time(nullptr)));
		switch (rand() % enum_digest_num)
		{
		case 0:
			val.val[16] = (rand() / c_digestmod[enum_digest_md5]) * c_digestmod[enum_digest_md5];
			digest = enum_digest_md5;
			break;
		case 1:
			val.val[16] = (rand() / c_digestmod[enum_digest_sha1]) * c_digestmod[enum_digest_sha1];
			digest = enum_digest_sha1;
			break;
		case 2:
			val.val[16] = (rand() / c_digestmod[enum_digest_sha2_256]) * c_digestmod[enum_digest_sha2_256];
			digest = enum_digest_sha2_256;
			break;
		case 3:
			val.val[16] = (rand() / c_digestmod[enum_digest_sha2_512] * c_digestmod[enum_digest_sha2_512]);
			digest = enum_digest_sha2_512;
			break;
		}
	}

	val.len = 17;
}

void PostProcessVal(enum_digest digest, _MDAVALUE& val)
{
	size_t len = val.len;
	if (len > 16)
	{
		return;
	}

	_MDAVALUE sha512;
	CalcSHA512(reinterpret_cast<uint8_t*>(val.val), val.len * 4, sha512, nullptr, 0);
	memcpy(&val.val[len], sha512.val, sizeof(uint32_t)*(17 - len));
		
	switch (digest)
	{
	case enum_digest_md5:
		val.val[16] = val.val[16] / c_digestmod[enum_digest_md5] * c_digestmod[enum_digest_md5];
		break;
	case enum_digest_sha1:
		val.val[16] = val.val[16] / c_digestmod[enum_digest_sha1] * c_digestmod[enum_digest_sha1];
		break;
	case enum_digest_sha2_256:
		val.val[16] = val.val[16] / c_digestmod[enum_digest_sha2_256] * c_digestmod[enum_digest_sha2_256];
		break;
	case enum_digest_sha2_512:
		val.val[16] = val.val[16] / c_digestmod[enum_digest_sha2_512] * c_digestmod[enum_digest_sha2_512];
		break;
	}

	val.len = 17;
}

void FindFiles(const char* path, std::set<std::string>& files, bool recursive)
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
				if (recursive)
				{
					if (strcmp(info.name, ".") && strcmp(info.name, ".."))
					{
						std::string folder = path;
						folder.append("\\");
						folder.append(info.name);
						FindFiles(folder.c_str(), files, recursive);
					}
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

void UpdateWithFile(const char* path, CMDA_Base* base)
{
// 	FileMap::FileMap* filemap = new FileMap::FileMap;
// 	if (filemap->Open(path))
// 	{
// 		while (filemap->Remap())
// 		{
// 			base->update(reinterpret_cast<uint8_t*>(filemap->GetBuffer()), filemap->GetLength());
// 		}
// 		filemap->Close();
// 	}
// 	delete filemap;

	mio::mio<mio::enum_mode_read>* file = new mio::mio<mio::enum_mode_read>;
	if(file->open_file(path))
	{
		uint8_t* buffer = new uint8_t[1024 * 1024 * 64];
		size_t readsize = 1024 * 1024 * 64;
		while ((readsize = file->read_file(buffer, 1024 * 1024 * 64)) != 0)
		{
			base->update(buffer, readsize);
		}
		delete[] buffer;
	}
	delete file;
}

bool Digest(const uint8_t* src, const size_t len, _MDAVALUE& val, const uint8_t* salt, const size_t saltlen)
{
	enum_digest digest;
	PreProcessVal(val, digest);

	switch (digest)
	{
	case enum_digest_md5:
		CalcMD5(src, len, val, salt, saltlen);
		break;
	case enum_digest_sha1:
		CalcSHA1(src, len, val, salt, saltlen);
		break;
	case enum_digest_sha2_256:
		CalcSHA256(src, len, val, salt, saltlen);
		break;
	case enum_digest_sha2_512:
		CalcSHA512(src, len, val, salt, saltlen);
		break;
	default: return false;
	}

	PostProcessVal(digest, val);

	return true;
}

bool DigestSel(enum_digest digest, const uint8_t* src, const size_t len, _MDAVALUE& val, const uint8_t* salt, const size_t saltlen)
{
	switch (digest)
	{
	case enum_digest_md5:
		CalcMD5(src, len, val, salt, saltlen);
		break;
	case enum_digest_sha1:
		CalcSHA1(src, len, val, salt, saltlen);
		break;
	case enum_digest_sha2_256:
		CalcSHA256(src, len, val, salt, saltlen);
		break;
	case enum_digest_sha2_512:
		CalcSHA512(src, len, val, salt, saltlen);
		break;
	default: return false;
	}

	PostProcessVal(digest, val);

	return false;
}

bool FileDigest(const char* path, _MDAVALUE& val)
{
	enum_digest digest;
	PreProcessVal(val, digest);

	CMDA_Base* base = nullptr;
	switch (digest)
	{
	case enum_digest_md5: CreateMD5(base); break;
	case enum_digest_sha1: CreateSHA1(base); break;
	case enum_digest_sha2_256: CreateSHA256(base); break;
	case enum_digest_sha2_512: CreateSHA512(base); break;
	}

	if (base != nullptr)
	{
		UpdateWithFile(path, base);

		base->finish(val);
	}

	switch (digest)
	{
	case enum_digest_md5: ReleaseMD5(base); break;
	case enum_digest_sha1: ReleaseSHA1(base); break;
	case enum_digest_sha2_256: ReleaseSHA256(base); break;
	case enum_digest_sha2_512: ReleaseSHA512(base); break;
	}

	PostProcessVal(digest, val);

	return true;
}

bool PathDigest(const char* path, _MDAVALUE& val, bool recursive)
{
	enum_digest digest;
	PreProcessVal(val, digest);

	std::set<std::string> files;
	files.clear();

	FindFiles(path, files, recursive);

	CMDA_Base* base = nullptr;
	switch (digest)
	{
	case enum_digest_md5: CreateMD5(base); break;
	case enum_digest_sha1: CreateSHA1(base); break;
	case enum_digest_sha2_256: CreateSHA256(base); break;
	case enum_digest_sha2_512: CreateSHA512(base); break;
	}

	if (base != nullptr)
	{
		std::set<std::string>::const_iterator it = files.begin();
		for (; it != files.end(); ++it)
		{
			UpdateWithFile(it->c_str(), base);
		}

		base->finish(val);
	}

	switch (digest)
	{
	case enum_digest_md5: ReleaseMD5(base); break;
	case enum_digest_sha1: ReleaseSHA1(base); break;
	case enum_digest_sha2_256: ReleaseSHA256(base); break;
	case enum_digest_sha2_512: ReleaseSHA512(base); break;
	}
	
	PostProcessVal(digest, val);

	return true;
}

bool ModuleDigest(enum_module module, _MDAVALUE& val)
{
	enum_digest digest;
	PreProcessVal(val, digest);

	switch (module)
	{
	case enum_all:
		PathDigest(c_strpath_all, val, true);
		break;
	default: return false;
	}

	PostProcessVal(digest, val);

	return true;
}
