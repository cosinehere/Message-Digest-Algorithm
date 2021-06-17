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
	//CalcMD5(s, 70, val, nullptr, 0);
	//CalcMD5(s, 70, val, salt, 3);
	//CalcSHA1(s, 70, val, nullptr, 0);
	//CalcSHA1(s, 70, val, salt, 3);
	CalcSHA256(s, 70, val, nullptr, 0);

	//printf("%u %u %u %u %u\n", val.pval[0], val.pval[1], val.pval[2], val.pval[3], val.pval[4]);

	char table[] = "0123456789abcdef";

// 	for (int a = 0; a < 4; ++a)
// 	{
// 		int b;
// 		std::string str1;
// 		std::string out = "";
// 		for (int i = 0; i < 4; ++i)
// 		{
// 			str1 = "";
// 			b = ((val.pval[a] >> i * 8) % (1 << 8)) & 0xff;
// 			for (int j = 0; j < 2; ++j)
// 			{
// 				str1.insert(0, 1, table[b % 16]);
// 				b /= 16;
// 			}
// 			out += str1;
// 		}
// 		printf("%s ", out.c_str());
// 	}

	for (int i = 0; i < 8; ++i)
	{
		std::string str;
		str.clear();
		uint32_t x = val.pval[i];
		while (x != 0)
		{
			uint8_t a = x & 0xff;
			x >>= 8;
			char ch[5] = { 0 };
			sprintf_s(ch, "%02x", a);
			str = ch + str;
		}
		printf("%s ", str.c_str());
	}
	printf("\n");

// 	FILE* file = nullptr;
// 	fopen_s(&file, "K:\\Project_Test\\Data63\\Report\\Report.cfg", "rb");
// 	
// 	fseek(file, 0L, SEEK_END);
// 	long len = ftell(file);
// 	printf("file len %d\n", len);
// 	fseek(file, 0L, SEEK_SET);
// 	uint8_t buf[2048] = { 0 };
// 	fread_s(buf, 2048, sizeof(uint8_t), len, file);
// 
// 	CalcSHA256(buf, len, val, nullptr, 0);
// 
// 	for (int i = 0; i < 8; ++i)
// 	{
// 		std::string str;
// 		str.clear();
// 		uint32_t x = val.pval[i];
// 		while (x != 0)
// 		{
// 			uint8_t a = x & 0xff;
// 			x >>= 8;
// 			char ch[5] = { 0 };
// 			sprintf_s(ch, "%02x", a);
// 			str = ch + str;
// 		}
// 		printf("%s ", str.c_str());
// 	}
// 	printf("\n");
// 
// 	fclose(file);
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
