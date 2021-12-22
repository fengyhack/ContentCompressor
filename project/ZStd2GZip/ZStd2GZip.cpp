#include "Compressor.h"
#include <string>

using namespace zio::compression;

int main(int argc, char** argv)
{
	if (argc < 3)
	{
		return -1;
	}

	std::string s1(argv[1]);
	std::string s2(argv[2]);
	if (argv[1][0] == '\"')
	{
		s1 = s1.substr(1, s1.length() - 2);
	}
	if (argv[2][0] == '\"')
	{
		s2 = s2.substr(1, s2.length() - 2);
	}

	ZStd2GZip(s1, s2);
	return 0;
}