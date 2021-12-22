#include "Compressor.h"
#include <string>
#include <chrono>

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
	double bpm;
	double cpr;
	ZStdCompressProfile(s1, s2, bpm, cpr);
	const double MPS = 1000.0 / (1 << 20);
	printf("speed:%.3fMB/s, ratio:%.3f\n", bpm * MPS, cpr);
#ifdef DEBUG
	(void)getchar();
#endif // DEBUG
	return 0;
}