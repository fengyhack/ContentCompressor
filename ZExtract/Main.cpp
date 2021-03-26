#include "Compressor.h"

using namespace zio::compression;

int main(int argc, char** argv)
{
	if (argc < 3)
	{
		return -1;
	}

	ZStd2Raw(argv[1], argv[2]);
	return 0;
}