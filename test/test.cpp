// test.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>

#include "mio.hpp"

#include "../MessageDigestAlgorithm/MDAdefines.h"
#pragma comment(lib,"../MessageDigestAlgorithm/Debug/MessageDigestAlgorithm")

#include <ctime>
#include <string>
#include <set>

constexpr uint32_t c_digestmod[] = { 65537,65539,65543,65551 };

enum enum_module
{
	enum_all = 0
};

constexpr char c_strpath_all[] = ".\\";

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

#ifdef _WIN32
void FindFiles(const char* path, std::set<std::string>& files, bool recursive)
{
	std::string format = path;
	format.append("\\*");
	WIN32_FIND_DATA find;
	HANDLE hfind = FindFirstFile(format.c_str(), &find);
	if (hfind != INVALID_HANDLE_VALUE)
	{
		do
		{
			if (find.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				if (recursive)
				{
					if (strcmp(find.cFileName, ".") && strcmp(find.cFileName, ".."))
					{
						std::string folder = path;
						folder.append("\\");
						folder.append(find.cFileName);
						FindFiles(folder.c_str(), files, recursive);
					}
				}
			}
			else
			{
				std::string fullpath = path;
				fullpath.append("\\");
				fullpath.append(find.cFileName);
				files.insert(fullpath);
				printf("%s\n", fullpath.c_str());
			}
		} while (FindNextFile(hfind, &find));
		FindClose(hfind);
	}
	// 	std::string format = path;
	// 	format.append("\\*");
	// 	struct _finddata_t info;
	// 	intptr_t hfile;
	// 	hfile = _findfirst(format.c_str(), &info);
	// 	if (hfile != -1)
	// 	{
	// 		do {
	// 			if (info.attrib&_A_SUBDIR)
	// 			{
	// 				if (recursive)
	// 				{
	// 					if (strcmp(info.name, ".") && strcmp(info.name, ".."))
	// 					{
	// 						std::string folder = path;
	// 						folder.append("\\");
	// 						folder.append(info.name);
	// 						FindFiles(folder.c_str(), files, recursive);
	// 					}
	// 				}
	// 			}
	// 			else
	// 			{
	// 				std::string fullpath = path;
	// 				fullpath.append("\\");
	// 				fullpath.append(info.name);
	// 				files.insert(fullpath);
	// 			}
	// 		} while (_findnext(hfile, &info) == 0);
	//
	// 		_findclose(hfile);
	// 	}
}
#else
void FindFiles(const char* path, std::set<std::string>& files, bool recursive)
{
}
#endif

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
	if (file->open_file(path))
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
	CreateBase(digest, base);

	if (base != nullptr)
	{
		UpdateWithFile(path, base);

		base->finish(val);
	}

	ReleaseBase(digest, base);

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
	CreateBase(digest, base);

	if (base != nullptr)
	{
		std::set<std::string>::const_iterator it = files.begin();
		for (; it != files.end(); ++it)
		{
			UpdateWithFile(it->c_str(), base);
		}

		base->finish(val);
	}

	ReleaseBase(digest, base);

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

int main()
{
	uint8_t s[71] = { "ageaimpahgdanjfleqjtpegasncmx.bnfbhjqethewqphdslangjdslagxhugpbqkrtewt" };
	_MDAVALUE val;
	uint8_t salt[4] = { "123" };

	//Digest(s, 70, val, nullptr, 0);
	//FileDigest("J:\\迅雷下载\\cn_windows_7_professional_with_sp1_vl_build_x86_dvd_u_677939.iso", val, nullptr, 0);
	//FileDigest("L:\\Users\\Administrator\\Downloads\\DXSDK_Aug09.exe", val);
	PathDigest("E:\\src_3.5_win7_2021_V1.07a\\_Release", val, false);
	//PathDigest("E:\\test", val, nullptr, 0);

	if (val.val[16] % c_digestmod[enum_digest_md5] == 0)
	{
		printf("MD5\n");
		char table[] = "0123456789abcdef";
		for (int a = 0; a < 17; ++a)
		{
			//int b;
			//std::string str1;
			//std::string out = "";
			//for (int i = 0; i < 4; ++i)
			//{
			//	str1 = "";
			//	b = ((val.val[a] >> i * 8) % (1 << 8)) & 0xff;
			//	for (int j = 0; j < 2; ++j)
			//	{
			//		str1.insert(0, 1, table[b % 16]);
			//		b /= 16;
			//	}
			//	out += str1;
			//}
			//printf("%s\n", out.c_str());
			printf("%08x\n", val.val[a]);
		}
		printf("\n");
	}
	else if (val.val[16] % c_digestmod[enum_digest_sha1] == 0)
	{
		printf("SHA1\n");
		for (int i = 0; i < 17; ++i)
		{
			printf("%08x\n", val.val[i]);
		}
		printf("\n");
	}
	else if (val.val[16] % c_digestmod[enum_digest_sha2_256] == 0)
	{
		printf("SHA2_256\n");
		for (int i = 0; i < 17; ++i)
		{
			printf("%08x\n", val.val[i]);
		}
		printf("\n");
	}
	else if (val.val[16] % c_digestmod[enum_digest_sha2_512] == 0)
	{
		printf("SHA2_512\n");
		for (int i = 0; i < 17; i += 2)
		{
			printf("%08x %08x\n", val.val[i + 1], val.val[i]);
		}
		printf("\n");
	}
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧:
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
