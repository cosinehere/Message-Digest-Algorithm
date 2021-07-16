// test.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>

#include "../MessageDigestAlgorithm/MDAdefines.h"
#pragma comment(lib,"../MessageDigestAlgorithm/Debug/MessageDigestAlgorithm.lib")

int main()
{
	uint8_t s[71] = { "ageaimpahgdanjfleqjtpegasncmx.bnfbhjqethewqphdslangjdslagxhugpbqkrtewt" };
	_MDAVALUE val;
	uint8_t salt[4] = { "123" };

	//Digest(s, 70, val, nullptr, 0);
	//FileDigest("J:\\迅雷下载\\cn_windows_7_professional_with_sp1_vl_build_x86_dvd_u_677939.iso", val, nullptr, 0);
	FileDigest("L:\\Users\\Administrator\\Downloads\\DXSDK_Aug09.exe", val);
	//PathDigest("E:\\src_3.5_win7_2021_V1.07a\\_Release", val, false);
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
		for (int i = 0; i < 17; i+=2)
		{
			printf("%08x %08x\n", val.val[i + 1],val.val[i]);
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
