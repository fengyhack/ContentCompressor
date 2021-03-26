/*
*****************************************************************************
*  Content Compression using ZStd(libzstd) or igzip(isa-l) with MD5 support
*  (ZStd license can be found under 'zstd' include directory, GPLv2/BSD)
*  Compression input: byte-stream
*  Compression output: compressed file (zstd or gzip format)
* --------------------------------------------------------------------------
*  update: 2021.01.21 @fengyh
*          Decompression from ZStd to Raw
* --------------------------------------------------------------------------
*  update: 2021.01.20 @fengyh
*          Converter from ZStd to GZip
* --------------------------------------------------------------------------
*  update: 2021.01.19 @fengyh
*          Compress chunk-by-chunk
*          End the last chunk (EOF)
* --------------------------------------------------------------------------
*  update: 2021.01.15 @fengyh
*          fix GZip crc32 error
* --------------------------------------------------------------------------
*  update: 2021.01.11 @fengyh
*          Compressor GZip and ZStd support
* --------------------------------------------------------------------------
*  update: 2021.01.05 @fengyh
*          Compressor ZStd support
* --------------------------------------------------------------------------
*****************************************************************************
*/

#ifndef COMPRESSOR_H
#define COMPRESSOR_H

#include <Windows.h> //file io
#include <string>
#include <stdint.h>
#include <zstd.h> //zstd
#include <igzip_lib.h> //isa-l gzip deflate
#include <crc.h> //isa-l gzip crc
#include <exception>

//----------------------------- MD5 Transform ------------------------------------

#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

#define FF(a, b, c, d, x, s, ac) { \
	          (a) += F ((b), (c), (d)) + (x) + ac; \
	          (a) = ROTATE_LEFT ((a), (s)); \
	          (a) += (b); }

#define GG(a, b, c, d, x, s, ac) { \
	          (a) += G ((b), (c), (d)) + (x) + ac; \
	          (a) = ROTATE_LEFT ((a), (s)); \
	          (a) += (b); }

#define HH(a, b, c, d, x, s, ac) { \
	          (a) += H ((b), (c), (d)) + (x) + ac; \
	          (a) = ROTATE_LEFT ((a), (s)); \
	          (a) += (b); }

#define II(a, b, c, d, x, s, ac) { \
	          (a) += I ((b), (c), (d)) + (x) + ac; \
	          (a) = ROTATE_LEFT ((a), (s)); \
	          (a) += (b); }

//-------------------------------------------------------------------------------

//MD5
namespace zio
{
	// hasing (MD5)
	// !!!NOTE: C++11 synatex used
	namespace hashing
	{
		//CONSTANTS
		//------------------------------------------------------------------
		constexpr int MD5_BLOCK_SIZE = 64;

		constexpr uint64_t S11 = 7;
		constexpr uint64_t S12 = 12;
		constexpr uint64_t S13 = 17;
		constexpr uint64_t S14 = 22;
		constexpr uint64_t S21 = 5;
		constexpr uint64_t S22 = 9;
		constexpr uint64_t S23 = 14;
		constexpr uint64_t S24 = 20;
		constexpr uint64_t S31 = 4;
		constexpr uint64_t S32 = 11;
		constexpr uint64_t S33 = 16;
		constexpr uint64_t S34 = 23;
		constexpr uint64_t S41 = 6;
		constexpr uint64_t S42 = 10;
		constexpr uint64_t S43 = 15;
		constexpr uint64_t S44 = 21;

		class MD5
		{
		public:
			MD5() :_finished(false)
			{
				Reset();
			}

			void Reset()
			{
				_finished = false;
				/* reset number of bits. */
				_count[0] = 0;
				_count[1] = 0;
				/* magic*/
				_state[0] = 0x67452301;
				_state[1] = 0xefcdab89;
				_state[2] = 0x98badcfe;
				_state[3] = 0x10325476;
			}

			void Update(const uint8_t* input, const size_t size)
			{
				_finished = false;

				/* Compute number of bytes mod 64 */
				auto index = (uint64_t)((_count[0] >> 3) & 0x3f);

				/* update number of bits */
				if ((_count[0] += ((uint64_t)size << 3)) < ((uint64_t)size << 3))
				{
					_count[1]++;
				}
				_count[1] += ((uint64_t)size >> 29);

				auto partLen = MD5_BLOCK_SIZE - index;
				/* transform as many times as possible. */
				if (size >= partLen)
				{
					memcpy(_buffer + index, input, partLen);
					_Transform(_buffer);
					uint8_t* buff = const_cast<uint8_t*>(input) + partLen;
					size_t residue = size - partLen;
					while (residue >= MD5_BLOCK_SIZE)
					{
						_Transform(buff);
						residue -= MD5_BLOCK_SIZE;
						buff += MD5_BLOCK_SIZE;
					}
					if (residue > 0)
					{
						/* Buffer remaining input */
						memcpy(_buffer, buff, residue);
					}
				}
				else
				{
					/* Buffer remaining input */
					memcpy(_buffer + index, input, size);
				}
			}

			void Final()
			{
				if (_finished)
				{
					return;
				}

				uint8_t bits[8];
				uint64_t oldState[4];
				uint64_t oldCount[2];
				uint64_t index, padLen;

				/* Save current state and count. */
				memcpy(oldState, _state, 16);
				memcpy(oldCount, _count, 8);

				/* Save number of bits */
				_Encode(_count, bits, 8);

				/* Pad out to 56 mod 64. */
				index = (uint64_t)((_count[0] >> 3) & 0x3f);
				constexpr int nR = MD5_BLOCK_SIZE - 8;
				padLen = (index < nR) ? (nR - index) : (MD5_BLOCK_SIZE + nR - index);
				Update(PADDING, padLen);

				/* Append length (before padding) */
				Update(bits, 8);

				/* Store state in digest */
				_Encode(_state, _digest, 16);

				/* Restore current state and count. */
				memcpy(_state, oldState, 16);
				memcpy(_count, oldCount, 8);

				_finished = true;
			}

			const uint8_t* Digest()
			{
				if (_finished)
				{
					Final();
				}
				return _digest;
			}

			std::string ToHexString(bool upperCase = false)
			{
				if (_finished)
				{
					Final();
				}
				return _BytesToHexString(_digest, 16, upperCase);
			}

		private:
			/* noncopyable */
			//MD5(const MD5&);
			//MD5& operator=(const MD5&);

			void _Transform(const uint8_t block[MD5_BLOCK_SIZE])
			{
				uint64_t a = _state[0];
				uint64_t b = _state[1];
				uint64_t c = _state[2];
				uint64_t d = _state[3];
				uint64_t x[16];

				_Decode(block, x, MD5_BLOCK_SIZE);

				/* Round 1 */
				FF(a, b, c, d, x[0], S11, 0xd76aa478); /* 1 */
				FF(d, a, b, c, x[1], S12, 0xe8c7b756); /* 2 */
				FF(c, d, a, b, x[2], S13, 0x242070db); /* 3 */
				FF(b, c, d, a, x[3], S14, 0xc1bdceee); /* 4 */
				FF(a, b, c, d, x[4], S11, 0xf57c0faf); /* 5 */
				FF(d, a, b, c, x[5], S12, 0x4787c62a); /* 6 */
				FF(c, d, a, b, x[6], S13, 0xa8304613); /* 7 */
				FF(b, c, d, a, x[7], S14, 0xfd469501); /* 8 */
				FF(a, b, c, d, x[8], S11, 0x698098d8); /* 9 */
				FF(d, a, b, c, x[9], S12, 0x8b44f7af); /* 10 */
				FF(c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
				FF(b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
				FF(a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
				FF(d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
				FF(c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
				FF(b, c, d, a, x[15], S14, 0x49b40821); /* 16 */

				/* Round 2 */
				GG(a, b, c, d, x[1], S21, 0xf61e2562); /* 17 */
				GG(d, a, b, c, x[6], S22, 0xc040b340); /* 18 */
				GG(c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
				GG(b, c, d, a, x[0], S24, 0xe9b6c7aa); /* 20 */
				GG(a, b, c, d, x[5], S21, 0xd62f105d); /* 21 */
				GG(d, a, b, c, x[10], S22, 0x2441453); /* 22 */
				GG(c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
				GG(b, c, d, a, x[4], S24, 0xe7d3fbc8); /* 24 */
				GG(a, b, c, d, x[9], S21, 0x21e1cde6); /* 25 */
				GG(d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
				GG(c, d, a, b, x[3], S23, 0xf4d50d87); /* 27 */
				GG(b, c, d, a, x[8], S24, 0x455a14ed); /* 28 */
				GG(a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
				GG(d, a, b, c, x[2], S22, 0xfcefa3f8); /* 30 */
				GG(c, d, a, b, x[7], S23, 0x676f02d9); /* 31 */
				GG(b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */

				/* Round 3 */
				HH(a, b, c, d, x[5], S31, 0xfffa3942); /* 33 */
				HH(d, a, b, c, x[8], S32, 0x8771f681); /* 34 */
				HH(c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
				HH(b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
				HH(a, b, c, d, x[1], S31, 0xa4beea44); /* 37 */
				HH(d, a, b, c, x[4], S32, 0x4bdecfa9); /* 38 */
				HH(c, d, a, b, x[7], S33, 0xf6bb4b60); /* 39 */
				HH(b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
				HH(a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
				HH(d, a, b, c, x[0], S32, 0xeaa127fa); /* 42 */
				HH(c, d, a, b, x[3], S33, 0xd4ef3085); /* 43 */
				HH(b, c, d, a, x[6], S34, 0x4881d05); /* 44 */
				HH(a, b, c, d, x[9], S31, 0xd9d4d039); /* 45 */
				HH(d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
				HH(c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
				HH(b, c, d, a, x[2], S34, 0xc4ac5665); /* 48 */

				/* Round 4 */
				II(a, b, c, d, x[0], S41, 0xf4292244); /* 49 */
				II(d, a, b, c, x[7], S42, 0x432aff97); /* 50 */
				II(c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
				II(b, c, d, a, x[5], S44, 0xfc93a039); /* 52 */
				II(a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
				II(d, a, b, c, x[3], S42, 0x8f0ccc92); /* 54 */
				II(c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
				II(b, c, d, a, x[1], S44, 0x85845dd1); /* 56 */
				II(a, b, c, d, x[8], S41, 0x6fa87e4f); /* 57 */
				II(d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
				II(c, d, a, b, x[6], S43, 0xa3014314); /* 59 */
				II(b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
				II(a, b, c, d, x[4], S41, 0xf7537e82); /* 61 */
				II(d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
				II(c, d, a, b, x[2], S43, 0x2ad7d2bb); /* 63 */
				II(b, c, d, a, x[9], S44, 0xeb86d391); /* 64 */

				_state[0] += a;
				_state[1] += b;
				_state[2] += c;
				_state[3] += d;
			}

			void _Encode(const uint64_t* input, uint8_t* output, size_t length)
			{
				for (size_t i = 0, j = 0; j < length; i++, j += 4)
				{
					output[j] = (uint8_t)(input[i] & 0xff);
					output[j + 1] = (uint8_t)((input[i] >> 8) & 0xff);
					output[j + 2] = (uint8_t)((input[i] >> 16) & 0xff);
					output[j + 3] = (uint8_t)((input[i] >> 24) & 0xff);
				}
			}

			void _Decode(const uint8_t* input, uint64_t* output, size_t length)
			{
				for (size_t i = 0, j = 0; j < length; i++, j += 4)
				{
					output[i] = ((uint64_t)input[j]) | (((uint64_t)input[j + 1]) << 8) |
						(((uint64_t)input[j + 2]) << 16) | (((uint64_t)input[j + 3]) << 24);
				}
			}

			std::string _BytesToHexString(const uint8_t* input, size_t length, bool upperCase)
			{
				std::string str;
				str.reserve(length << 1);
				if (upperCase)
				{
					for (size_t i = 0; i < length; ++i)
					{
						int t = input[i];
						int a = t / 16;
						int b = t % 16;
						str.append(1, HEX_UPPER_CASE[a]);
						str.append(1, HEX_UPPER_CASE[b]);
					}
				}
				else
				{
					for (size_t i = 0; i < length; ++i)
					{
						int t = input[i];
						int a = t / 16;
						int b = t % 16;
						str.append(1, HEX_LOWER_CASE[a]);
						str.append(1, HEX_LOWER_CASE[b]);
					}
				}
				return str;
			}

		private:
			uint64_t _state[4];	/* state (ABCD) */
			uint64_t _count[2];	/* number of bits, modulo 2^64 (low-order word first) */
			uint8_t _buffer[MD5_BLOCK_SIZE]; /* input buffer */
			uint8_t _digest[16]; /* message digest */
			bool _finished; /* calculate finished ? */

			const uint8_t PADDING[MD5_BLOCK_SIZE] = { 0x80 };	/* padding for calculate */
			const size_t BUFFER_SIZE = 1024;
			const char HEX_LOWER_CASE[16] =
			{
				'0', '1', '2', '3',	'4', '5', '6', '7',
				'8', '9', 'a', 'b',	'c', 'd', 'e', 'f'
			};
			const char HEX_UPPER_CASE[16] =
			{
				'0', '1', '2', '3',	'4', '5', '6', '7',
				'8', '9', 'A', 'B',	'C', 'D', 'E', 'F'
			};
		};

	}
}

namespace zio
{
	//Compression
	namespace compression
	{
		/*
		 OutputMode: Write|Append
		*/
		enum class Mode
		{
			/*Nop*/
			None,
			/*write to file (create or overwrite)*/
			Write,
			/*append to file (create or append to the end)*/
			Append
		};

		/*
		 * OutputFormat: GZip|ZStd
		*/
		enum class Format
		{
			GZip = 0,
			ZStd = 1,
			DEFAULT = GZip,
			MIN = 0,
			MAX = 1
		};

		/*
		 @brief convert from Int to Format
		*/
		static Format Convert(const int format)
		{
			if (format < (int)Format::MIN || format >(int)Format::MAX)
			{
				return Format::DEFAULT;
			}

			return (Format)format;
		}

		/*
		 @brief convert from Str to Format
		*/
		static Format Convert(const std::string format)
		{
			if (format.empty())
			{
				return Format::DEFAULT;
			}

			if (_stricmp(format.c_str(), "gzip") == 0)
			{
				return Format::GZip;
			}
			else if (_stricmp(format.c_str(), "zstd") == 0)
			{
				return Format::ZStd;
			}
			else
			{
				if (isdigit(format[0]))
				{
					for (auto i = 1; i < format.length(); ++i)
					{
						if (!isdigit(format[i]))
						{
							return Format::DEFAULT;
						}
					}
					auto num = atoi(format.c_str());
					return Convert(num);
				}
				else
				{
					return Format::DEFAULT;
				}
			}
		}

		/*
		 @brief get compression format name
		*/
		static std::string ToString(Format format)
		{
			switch (format)
			{
			case Format::GZip:
				return "gzip";
			case Format::ZStd:
				return "zstd";
			default:
				return "invalid";
			}
		}

		typedef struct isal_zstream isal_zstream;

		/*
		 Compressor class, compressed/output as file
		*/
		class Compressor
		{
		public:
			/*
			 @brief Compressor constructor
			 @param outfile: output filename
			 @param format: compression format, GZip|ZStd, default is 'GZip'
			 @param mode: FileMode = Read|Write|Append, default is 'Write'
			 @param genMD5: generate MD5 or not, default is 'false'
			*/
			Compressor(const std::string& outfile, Format format = Format::GZip, const Mode mode = Mode::Write, bool genMD5 = false)
				:fName(outfile),
				cFormat(format),
				fMode(mode),
				bGenMD5(genMD5),
				fSize(0),
				fCursor(0),
				fHandle(nullptr),
				currentInputBuffer(nullptr),
				compressedBuffer(nullptr),
				inputBufferCursor(0),
				compressedBufferSize(0),
				compressedBufferSizeLimit(0),
				compressedBufferCapacity(0),
				inputChunkSize(0),
				currentInputSize(0),
				outputChunkSize(0),
				bEndOfStream(false),
				zstCtx(nullptr),
				zstInput({ nullptr,0,0 }),
				zstOutput({ nullptr,0,0 }),
				igzStream(nullptr),
				igzLevelBuff(nullptr),
				igzCrc(0),
				totalInputSize(0),
				bClosed(false)
			{
				if (mode == Mode::None || outfile.empty())
				{
					return;
				}

				DWORD share = GENERIC_READ | GENERIC_WRITE;
				DWORD creation = OPEN_EXISTING;

				switch (mode)
				{
				case Mode::Write:
					share = GENERIC_WRITE;
					creation = CREATE_ALWAYS;
					break;
				case Mode::Append:
					share = GENERIC_READ | GENERIC_WRITE;
					creation = OPEN_EXISTING;
					break;
				default:
					share = GENERIC_READ | GENERIC_WRITE;
					creation = OPEN_EXISTING;
					break;
				}

				fHandle = CreateFileA(
					outfile.c_str(),
					share,
					NULL,
					NULL,
					creation,
					FILE_ATTRIBUTE_NORMAL,
					NULL);

				if (fHandle == INVALID_HANDLE_VALUE)
				{
					return;
				}

				if (mode == Mode::Append)
				{
					DWORD dwFileSizeHigh;
					DWORD dwFileSizeLow = ::GetFileSize(fHandle, &dwFileSizeHigh);
					fSize = dwFileSizeLow | (((__int64)dwFileSizeHigh) << 32);
				}

				if (mode == Mode::Write || mode == Mode::Append)
				{

					switch (cFormat)
					{
					case Format::GZip:
					{
						inputChunkSize = IGZ_CHUNK_CAPACITY;
						outputChunkSize = IGZ_CHUNK_CAPACITY;
						currentInputBuffer = new uint8_t[inputChunkSize];
						compressedBufferSizeLimit = COMPRESS_BUFF_SIZE_LIMIT;
						compressedBufferCapacity = compressedBufferSizeLimit + outputChunkSize;
						compressedBuffer = new uint8_t[compressedBufferCapacity];
						igzStream = new isal_zstream;
						igzLevelBuff = new uint8_t[IGZ_LEVEL_BUFF_SIZE];
						//reset gzip
						_ResetIGZIP(IGZIP_GZIP_NO_HDR);
						//GZ header
						isal_gzip_header gz_hdr;
						isal_gzip_header_init(&gz_hdr);
						isal_write_gzip_header(igzStream, &gz_hdr);
						compressedBufferSize = igzStream->total_out;
						_WriteAndReset();
						//reset gzip
						_ResetIGZIP();
					}
					break;
					case Format::ZStd:
					{
						inputChunkSize = ZSTD_CStreamInSize();
						outputChunkSize = ZSTD_CStreamOutSize();
						currentInputBuffer = new uint8_t[inputChunkSize];
						compressedBufferSizeLimit = COMPRESS_BUFF_SIZE_LIMIT;
						compressedBufferCapacity = compressedBufferSizeLimit + outputChunkSize;
						compressedBuffer = new uint8_t[compressedBufferCapacity];
						zstCtx = ZSTD_createCCtx();
						ZSTD_CCtx_setParameter(zstCtx, ZSTD_c_compressionLevel, ZSTD_COMPRESS_LEVEL);
						ZSTD_CCtx_setParameter(zstCtx, ZSTD_c_checksumFlag, 1);
						//ZSTD_CCtx_setParameter(zstCtx, ZSTD_c_nbWorkers, 1);
					}
					break;
					}
				}
			}

			/*
			 @brief Compressor constructor (ovr default)
			*/
			Compressor()
				:fName(""),
				cFormat(Format::GZip),
				fMode(Mode::None),
				bGenMD5(false),
				fSize(0),
				fCursor(0),
				fHandle(nullptr),
				currentInputBuffer(nullptr),
				compressedBuffer(nullptr),
				inputBufferCursor(0),
				compressedBufferSize(0),
				compressedBufferSizeLimit(0),
				compressedBufferCapacity(0),
				inputChunkSize(0),
				currentInputSize(0),
				outputChunkSize(0),
				bEndOfStream(false),
				zstCtx(nullptr),
				zstInput({ nullptr,0,0 }),
				zstOutput({ nullptr,0,0 }),
				igzStream(nullptr),
				igzLevelBuff(nullptr),
				igzCrc(0),
				totalInputSize(0),
				bClosed(false)
			{
				//
			}

			/*
			 @brief Compressor destructor, auto flush buffer and close file
			 */
			~Compressor()
			{
				Close();
			}

			/*
			 @brief set parameters (can be used after default constructor
			 @param outfile: output filename
			 @param mode: Write|Append
			 @param genMD5: generate MD5 or not
			 @return reference to this class
			*/
			Compressor& Configure(const std::string& outfile, const Mode mode = Mode::Write, bool genMD5 = false)
			{
				if (fHandle)
				{
					throw std::exception("configure_invalid_overwrite");
				}

				if (mode == Mode::None || outfile.empty())
				{
					throw* this;
				}

				DWORD share = GENERIC_READ | GENERIC_WRITE;
				DWORD creation = OPEN_EXISTING;

				switch (mode)
				{
				case Mode::Write:
					share = GENERIC_WRITE;
					creation = CREATE_ALWAYS;
					break;
				case Mode::Append:
					share = GENERIC_READ | GENERIC_WRITE;
					creation = OPEN_EXISTING;
					break;
				default:
					share = GENERIC_READ | GENERIC_WRITE;
					creation = OPEN_EXISTING;
					break;
				}

				fHandle = CreateFileA(
					outfile.c_str(),
					share,
					NULL,
					NULL,
					creation,
					FILE_ATTRIBUTE_NORMAL,
					NULL);

				if (fHandle == INVALID_HANDLE_VALUE)
				{
					return *this;
				}

				if (mode == Mode::Append)
				{
					DWORD dwFileSizeHigh;
					DWORD dwFileSizeLow = ::GetFileSize(fHandle, &dwFileSizeHigh);
					fSize = dwFileSizeLow | (((__int64)dwFileSizeHigh) << 32);
				}

				if (mode == Mode::Write || mode == Mode::Append)
				{

					switch (cFormat)
					{
					case Format::GZip:
					{
						inputChunkSize = IGZ_CHUNK_CAPACITY;
						outputChunkSize = IGZ_CHUNK_CAPACITY;
						currentInputBuffer = new uint8_t[inputChunkSize];
						compressedBufferSizeLimit = COMPRESS_BUFF_SIZE_LIMIT;
						compressedBufferCapacity = compressedBufferSizeLimit + outputChunkSize;
						compressedBuffer = new uint8_t[compressedBufferCapacity];
						igzStream = new isal_zstream;
						igzLevelBuff = new uint8_t[IGZ_LEVEL_BUFF_SIZE];
						//reset gzip
						_ResetIGZIP(IGZIP_GZIP_NO_HDR);
						//GZ header
						isal_gzip_header gz_hdr;
						isal_gzip_header_init(&gz_hdr);
						isal_write_gzip_header(igzStream, &gz_hdr);
						compressedBufferSize = igzStream->total_out;
						_WriteAndReset();
						//reset gzip
						_ResetIGZIP();
					}
					break;
					case Format::ZStd:
					{
						inputChunkSize = ZSTD_CStreamInSize();
						outputChunkSize = ZSTD_CStreamOutSize();
						currentInputBuffer = new uint8_t[inputChunkSize];
						compressedBufferSizeLimit = COMPRESS_BUFF_SIZE_LIMIT;
						compressedBufferCapacity = compressedBufferSizeLimit + outputChunkSize;
						compressedBuffer = new uint8_t[compressedBufferCapacity];
						zstCtx = ZSTD_createCCtx();
						ZSTD_CCtx_setParameter(zstCtx, ZSTD_c_compressionLevel, ZSTD_COMPRESS_LEVEL);
						ZSTD_CCtx_setParameter(zstCtx, ZSTD_c_checksumFlag, 1);
						//ZSTD_CCtx_setParameter(zstCtx, ZSTD_c_nbWorkers, 1);
					}
					break;
					}
				}

				return *this;
			}

			/*
			 @brief Compress left raw data, flush to file, and then close.
					Delete the file if it is empty.
			*/
			void Close()
			{
				if (bClosed)
				{
					return;
				}

				if (fHandle)
				{
					if (!bEndOfStream)
					{
						_EndAndWrite();
					}

					FlushFileBuffers(fHandle);
					CloseHandle(fHandle);
					fHandle = nullptr;
				}

				if (!fName.empty() && (fMode == Mode::Write || fMode == Mode::Append) && totalInputSize == 0)
				{
					DeleteFileA(fName.c_str());
					fSize = 0;
				}

				if (zstCtx)
				{
					ZSTD_freeCCtx(zstCtx);
					zstCtx = nullptr;
				}

				if (igzLevelBuff)
				{
					delete[] igzLevelBuff;
					igzLevelBuff = nullptr;
				}

				if (igzStream)
				{
					delete igzStream;
					igzStream = nullptr;
				}

				if (currentInputBuffer)
				{
					delete[] currentInputBuffer;
					currentInputBuffer = nullptr;
				}
				if (compressedBuffer)
				{
					delete[] compressedBuffer;
					compressedBuffer = nullptr;
				}

				fCursor = 0;
				inputBufferCursor = 0;
				currentInputSize = 0;
				compressedBufferSize = 0;
				bClosed = true;
			}

			/*
			 @brief Put data to the raw buffer and then compress.
			 @param data: input data (raw/binary)
			 @param size: input size (how many bytes)
			 @param isLast: the last chunk or not
			*/
			void Put(void* data, uint32_t size, bool isLast = false)
			{
				if (bEndOfStream && size > 0)
				{
					throw std::exception("end_of_stream");
				}

				if (size > 0)
				{
					totalInputSize += size;
					uint8_t* ptr = (uint8_t*)data;
					uint32_t residue = size;
					if (currentInputSize > 0)
					{
						if (currentInputSize < inputChunkSize)
						{
							uint32_t pad = inputChunkSize - currentInputSize;
							if (pad > size)
							{
								pad = size;
							}
							memcpy(currentInputBuffer + currentInputSize, data, pad);
							ptr += pad;
							residue -= pad;
							currentInputSize += pad;
							if ((isLast && currentInputSize > 0) || currentInputSize == inputChunkSize)
							{
								_CompressAndWrite(currentInputBuffer, currentInputSize, (isLast && residue == 0));
								currentInputSize = 0;
							}
						}
						else
						{
							_CompressAndWrite(currentInputBuffer, currentInputSize);
							currentInputSize = 0;
						}
					}
					while (residue >= inputChunkSize)
					{
						_CompressAndWrite(ptr, inputChunkSize, (isLast && residue <= inputChunkSize));
						ptr += inputChunkSize;
						residue -= inputChunkSize;
					}
					if (residue > 0)
					{
						if (isLast)
						{
							_CompressAndWrite(ptr, residue, true);
						}
						else
						{
							memcpy(currentInputBuffer + currentInputSize, ptr, residue);
							currentInputSize += residue;
						}
					}
				}
				else
				{
					if (isLast && currentInputSize > 0)
					{
						_CompressAndWrite(currentInputBuffer, currentInputSize, true);
						currentInputSize = 0;
					}
				}
			}

			/*
			 @brief get total input size, currently
			*/
			uint64_t InputSize() const
			{
				return totalInputSize;
			}

			/*
			 @brief get file size, currently
			 @param flushed: 'true' get the actual file size after flush
			*/
			uint64_t FileSize(bool flushed = true) const
			{
				if (flushed && (fMode == Mode::Write || fMode == Mode::Append) && totalInputSize == 0)
				{
					return 0;
				}
				else
				{
					return fSize;
				}
			}

			/*
			 @brief get md5
			 @return md5 hex string
			 @param md5fx
					true: <md5HexStr> <delim> <filename>
					false: <md5HexStr>
			*/
			std::string GetHashStr(bool md5fx, const std::string& delim)
			{
				if (bGenMD5 && !fName.empty())
				{
					auto hash = md5x.ToHexString();
					if (md5fx)
					{
						char drive[_MAX_DRIVE] = { 0 };
						char dir[_MAX_DIR] = { 0 };
						char fname[_MAX_FNAME] = { 0 };
						char ext[_MAX_EXT] = { 0 };
						_splitpath_s(fName.c_str(), drive, dir, fname, ext);
						return hash + delim + fname + ext;
					}
					else
					{
						return hash;
					}
				}
				else
				{
					return "";
				}
			}

		private:
			void _CompressAndWrite(uint8_t* input, uint32_t size, bool isLast = false)
			{
				switch (cFormat)
				{
				case Format::GZip:
					_CompressAndWriteGZIP(input, size, (isLast && size <= inputChunkSize));
					break;
				case Format::ZStd:
					_CompressAndWriteZSTD(input, size, (isLast && size <= inputChunkSize));
					break;
				}
			}

			void _EndAndWrite()
			{
				switch (cFormat)
				{
				case Format::GZip:
					_EndAndWriteGZIP();
					break;
				case Format::ZStd:
					_EndAndWriteZSTD();
					break;
				default:
					bEndOfStream = true;
					break;
				}
			}

			void _CompressAndWriteGZIP(uint8_t* input, uint32_t size, bool isLast)
			{
				if (compressedBufferSize >= compressedBufferSizeLimit)
				{
					_WriteAndReset();
				}

				if ((size == 0) || (!isLast && size < inputChunkSize))
				{
					return;
				}

				igzCrc = crc32_gzip_refl(igzCrc, input, size);

				igzStream->end_of_stream = isLast ? 1 : 0;
				igzStream->flush = isLast ? NO_FLUSH : FULL_FLUSH;
				igzStream->next_in = input;
				igzStream->avail_in = size;
				uint32_t availableOutputSize = 0;
				do
				{
					availableOutputSize = compressedBufferSizeLimit - compressedBufferSize;
					igzStream->next_out = compressedBuffer + compressedBufferSize;
					igzStream->avail_out = availableOutputSize;
					isal_deflate(igzStream);
					//!!!IMPORTANT!!! Do NOT use 'total_out'
					compressedBufferSize += (availableOutputSize - igzStream->avail_out);
					if (compressedBufferSize >= compressedBufferSizeLimit)
					{
						_WriteAndReset();
					}
				} while (igzStream->avail_out == 0);

				if (isLast)
				{
					if (compressedBufferSize >= compressedBufferSizeLimit)
					{
						_WriteAndReset();
					}

					const int Ne = 4;
					memcpy(compressedBuffer + compressedBufferSize, &igzCrc, Ne);
					compressedBufferSize += Ne;
					uint32_t inputSizeLo = totalInputSize & UINT32_MAX; // lower 32bits
					memcpy(compressedBuffer + compressedBufferSize, &inputSizeLo, Ne);
					compressedBufferSize += Ne;
					_WriteAndReset();

					if (bGenMD5)
					{
						md5x.Final();
					}
					bEndOfStream = true;
				}
			}

			void _EndAndWriteGZIP()
			{
				if (bEndOfStream)
				{
					return;
				}

				if (compressedBufferSize >= compressedBufferSizeLimit)
				{
					_WriteAndReset();
				}

				if (currentInputSize > 0)
				{
					igzCrc = crc32_gzip_refl(igzCrc, currentInputBuffer, currentInputSize);
				}

				igzStream->end_of_stream = 1;
				igzStream->flush = NO_FLUSH;
				igzStream->next_in = currentInputSize > 0 ? currentInputBuffer : nullptr;
				igzStream->avail_in = currentInputSize;
				uint32_t availableOutputSize = 0;
				do
				{
					availableOutputSize = compressedBufferSizeLimit - compressedBufferSize;
					igzStream->next_out = compressedBuffer + compressedBufferSize;
					igzStream->avail_out = availableOutputSize;
					isal_deflate(igzStream);
					//!!!IMPORTANT!!! Do NOT use 'total_out'
					compressedBufferSize += (availableOutputSize - igzStream->avail_out);
					if (compressedBufferSize >= compressedBufferSizeLimit)
					{
						_WriteAndReset();
					}
				} while (igzStream->avail_out == 0);

				if (compressedBufferSize >= compressedBufferSizeLimit)
				{
					_WriteAndReset();
				}

				const int Ne = 4;
				memcpy(compressedBuffer + compressedBufferSize, &igzCrc, Ne);
				compressedBufferSize += Ne;
				uint32_t inputSizeLo = totalInputSize & UINT32_MAX; // lower 32bits
				memcpy(compressedBuffer + compressedBufferSize, &inputSizeLo, Ne);
				compressedBufferSize += Ne;
				_WriteAndReset();

				if (bGenMD5)
				{
					md5x.Final();
				}
				bEndOfStream = true;
			}

			void _CompressAndWriteZSTD(uint8_t* input, uint32_t size, bool isLast)
			{
				if (compressedBufferSize >= compressedBufferSizeLimit)
				{
					_WriteAndReset();
				}

				if ((size == 0) || (!isLast && size < inputChunkSize))
				{
					return;
				}

				zstInput.src = input;
				zstInput.size = size;
				zstInput.pos = 0;
				zstOutput.dst = compressedBuffer + compressedBufferSize;
				zstOutput.size = outputChunkSize;

				size_t remain = 0;
				ZSTD_EndDirective mode = isLast ? ZSTD_e_end : ZSTD_e_continue;
				bool finished = false;
				do
				{
					zstOutput.pos = 0;
					remain = ZSTD_compressStream2(zstCtx, &zstOutput, &zstInput, mode);
					compressedBufferSize += zstOutput.pos;
					if (compressedBufferSize >= compressedBufferSizeLimit)
					{
						_WriteAndReset();
						zstOutput.dst = compressedBuffer;
					}
					else
					{
						zstOutput.dst = compressedBuffer + compressedBufferSize;
					}
					finished = (remain == 0);
				} while (!finished);

				if (isLast)
				{
					_WriteAndReset();
					if (bGenMD5)
					{
						md5x.Final();
					}
					bEndOfStream = true;
				}
			}

			void _EndAndWriteZSTD()
			{
				if (bEndOfStream)
				{
					return;
				}

				if (compressedBufferSize >= compressedBufferSizeLimit)
				{
					_WriteAndReset();
				}

				zstInput.src = currentInputSize > 0 ? currentInputBuffer : nullptr;
				zstInput.size = currentInputSize;
				zstInput.pos = 0;
				zstOutput.dst = compressedBuffer + compressedBufferSize;
				zstOutput.size = outputChunkSize;

				size_t remain = 0;
				ZSTD_EndDirective mode = ZSTD_e_end;
				bool finished = false;
				do
				{
					zstOutput.pos = 0;
					remain = ZSTD_compressStream2(zstCtx, &zstOutput, &zstInput, mode);
					compressedBufferSize += zstOutput.pos;
					if (compressedBufferSize >= compressedBufferSizeLimit)
					{
						_WriteAndReset();
						zstOutput.dst = compressedBuffer;
					}
					else
					{
						zstOutput.dst = compressedBuffer + compressedBufferSize;
					}
					finished = (remain == 0);
				} while (!finished);

				_WriteAndReset();
				if (bGenMD5)
				{
					md5x.Final();
				}
				bEndOfStream = true;
			}

			//!!! 'igzStream' and 'compressedBuffer' MUST be created first
			void _ResetIGZIP(uint16_t gzFlag = IGZIP_DEFLATE)
			{
				isal_deflate_init(igzStream);
				igzStream->end_of_stream = 0;
				igzStream->flush = NO_FLUSH;
				igzStream->level = IGZ_COMPRESS_LEVEL;
				igzStream->level_buf = igzLevelBuff;
				igzStream->level_buf_size = IGZ_LEVEL_BUFF_SIZE;
				igzStream->next_in = nullptr;
				igzStream->avail_in = 0;
				igzStream->next_out = compressedBuffer;
				igzStream->avail_out = outputChunkSize;
				igzStream->gzip_flag = gzFlag;
			}

			size_t _WriteAndReset(bool append = true, bool flush = false)
			{
				if (fHandle == nullptr)
				{
					throw std::exception("FileHandle is null");
				}

				if (fMode != Mode::Write && fMode != Mode::Append)
				{
					throw std::exception("FileMode must be \'Write\' or \'Append\'");
				}

				if (compressedBufferSize == 0)
				{
					return 0;
				}

				if (append || fMode == Mode::Append)
				{
					SetFilePointer(fHandle, 0, NULL, FILE_END);
				}
				else
				{
					//overwrite
					SetFilePointer(fHandle, 0, NULL, FILE_BEGIN);
					fSize = 0;
					if (bGenMD5)
					{
						md5x.Reset();
					}
				}

				DWORD dwBytes = 0;
				WriteFile(fHandle, compressedBuffer, compressedBufferSize, &dwBytes, NULL);
				if (bGenMD5)
				{
					md5x.Update(compressedBuffer, compressedBufferSize);
				}
				compressedBufferSize = 0;
				if (flush)
				{
					FlushFileBuffers(fHandle);
				}

				fSize += dwBytes;
				fCursor = fSize;

				return dwBytes;
			}

		private:
			uint8_t*       currentInputBuffer;
			uint8_t*       compressedBuffer;
			uint32_t       currentInputSize;
			uint32_t       inputBufferCursor;
			uint32_t       compressedBufferCapacity;
			uint32_t       compressedBufferSize;
			uint32_t       compressedBufferSizeLimit;
			isal_zstream*  igzStream;
			uint8_t*       igzLevelBuff;
			uint32_t       igzCrc;
			uint64_t       totalInputSize;
			uint32_t       inputChunkSize;
			uint32_t       outputChunkSize;
			bool           bEndOfStream;
			ZSTD_CCtx*     zstCtx;
			ZSTD_inBuffer  zstInput;
			ZSTD_outBuffer zstOutput;
			Format         cFormat;

			/*
			 zstd compress level, default 1
			*/
			const int ZSTD_COMPRESS_LEVEL = 1;

			/*
			 gzip compress level, default 1
			*/
			const int IGZ_COMPRESS_LEVEL = 1;

			/*
			 gzip level buffer size (level1 large)
			*/
			const int IGZ_LEVEL_BUFF_SIZE = ISAL_DEF_LVL1_DEFAULT;

			/*
			 gzip chunk size (8KB)
			*/
			const int IGZ_CHUNK_CAPACITY = 8192;

			/*
			 output (compressed data) buffer size limit£¬1MB
			 flush to file immediately if data size exceeds
			*/
			const int COMPRESS_BUFF_SIZE_LIMIT = 1 << 20;

		private:
			bool              bGenMD5;
			zio::hashing::MD5 md5x;

		private:
			std::string fName;
			Mode        fMode;
			uint64_t    fCursor;
			uint64_t    fSize;
			HANDLE      fHandle;
			bool        bClosed;
		};

		/*
		* @brief convert from ZStd to GZip
		* @param infile: input ZStd compressed file
		* @param outfile: output GZip compressed file
		* @return true if success, false if fail
		*/
		static bool ZStd2GZip(const std::string& infile, const std::string& outfile)
		{
			HANDLE ifHandle = CreateFileA(
				infile.c_str(),
				GENERIC_READ,
				NULL,
				NULL,
				OPEN_EXISTING,
				FILE_ATTRIBUTE_NORMAL,
				NULL);

			HANDLE ofHandle = CreateFileA(
				outfile.c_str(),
				GENERIC_WRITE,
				NULL,
				NULL,
				CREATE_ALWAYS,
				FILE_ATTRIBUTE_NORMAL,
				NULL);

			if (ifHandle == INVALID_HANDLE_VALUE || ofHandle == INVALID_HANDLE_VALUE)
			{
				return false;
			}

			DWORD dwFileSizeHigh;
			DWORD dwFileSizeLow = ::GetFileSize(ifHandle, &dwFileSizeHigh);
			uint64_t ifSize = dwFileSizeLow | (((__int64)dwFileSizeHigh) << 32);

			const int GZIP_HDR_LEN = 10;
			const uint8_t GZIP_HDR_DATA[] = { 0x1F,0x8B,0x08,0x00,0x00,0x00,0x00,0x00,0x00,0xFF };
			WriteFile(ofHandle, GZIP_HDR_DATA, GZIP_HDR_LEN, NULL, NULL);

			uint32_t zstInputChunkSize = ZSTD_DStreamInSize();
			uint32_t zstOutputChunkSize = ZSTD_DStreamOutSize();
			auto zstDtx = ZSTD_createDCtx();
			uint8_t* zstInputChunkBuffer = new uint8_t[zstInputChunkSize];
			uint8_t* igzInputChunkBuffer = new uint8_t[zstOutputChunkSize];
			uint8_t* igzOutputChunkBuffer = new uint8_t[zstOutputChunkSize];
			ZSTD_inBuffer  zstInput;
			ZSTD_outBuffer zstOutput;
			zstInput.src = zstInputChunkBuffer;
			zstInput.size = zstInputChunkSize;
			zstInput.pos = 0;
			zstOutput.dst = igzInputChunkBuffer;
			zstOutput.size = zstOutputChunkSize;
			zstOutput.pos = 0;
			DWORD dwSize = 0;
			isal_zstream* igzStream = new isal_zstream;
			isal_deflate_init(igzStream);
			uint64_t totalSize = 0;
			size_t outputSize = 0;
			uint32_t crc = 0;
			bool isLastChunk = false;
			uint64_t residue = ifSize;
			while (residue > 0)
			{
				(void)ReadFile(ifHandle, zstInputChunkBuffer, zstInputChunkSize, &dwSize, NULL);
				zstInput.size = dwSize;
				zstInput.pos = 0;
				residue -= dwSize;
				while (zstInput.pos < zstInput.size)
				{
					zstOutput.pos = 0;
					ZSTD_decompressStream(zstDtx, &zstOutput, &zstInput);
					crc = crc32_gzip_refl(crc, igzInputChunkBuffer, zstOutput.pos);
					isLastChunk = (residue == 0) && (zstInput.pos == zstInput.size);
					do
					{
						igzStream->end_of_stream = isLastChunk ? 1 : 0;
						igzStream->flush = isLastChunk ? NO_FLUSH : FULL_FLUSH;
						igzStream->next_in = igzInputChunkBuffer;
						igzStream->avail_in = zstOutput.pos;
						igzStream->next_out = igzOutputChunkBuffer;
						igzStream->avail_out = zstOutputChunkSize;
						isal_deflate(igzStream);
						outputSize = zstOutputChunkSize - igzStream->avail_out;
						totalSize += zstOutput.pos;
						if (outputSize > 0)
						{
							WriteFile(ofHandle, igzOutputChunkBuffer, outputSize, NULL, NULL);
						}
					} while (igzStream->avail_out == 0);
				}
			}

			WriteFile(ofHandle, &crc, 4, NULL, NULL);
			uint32_t sizeLo = totalSize & UINT32_MAX; // lower 32bits
			WriteFile(ofHandle, &sizeLo, 4, NULL, NULL);

			FlushFileBuffers(ofHandle);
			CloseHandle(ofHandle);
			CloseHandle(ifHandle);

			ZSTD_freeDCtx(zstDtx);

			delete igzStream;
			delete[] zstInputChunkBuffer;
			delete[] igzInputChunkBuffer;
			delete[] igzOutputChunkBuffer;

			return true;
		}

		/*
		* @brief decompress ZStd file
		* @param infile: input ZStd compressed file
		* @param outfile: output decompressed file
		* @return true if success, false if fail
		*/
		static bool ZStd2Raw(const std::string& infile, const std::string& outfile)
		{
			HANDLE ifHandle = CreateFileA(
				infile.c_str(),
				GENERIC_READ,
				NULL,
				NULL,
				OPEN_EXISTING,
				FILE_ATTRIBUTE_NORMAL,
				NULL);

			HANDLE ofHandle = CreateFileA(
				outfile.c_str(),
				GENERIC_WRITE,
				NULL,
				NULL,
				CREATE_ALWAYS,
				FILE_ATTRIBUTE_NORMAL,
				NULL);

			if (ifHandle == INVALID_HANDLE_VALUE || ofHandle == INVALID_HANDLE_VALUE)
			{
				return false;
			}

			DWORD dwFileSizeHigh;
			DWORD dwFileSizeLow = ::GetFileSize(ifHandle, &dwFileSizeHigh);
			uint64_t ifSize = dwFileSizeLow | (((__int64)dwFileSizeHigh) << 32);


			size_t inputChunkSize = ZSTD_CStreamInSize();
			size_t outputChunkSize = ZSTD_CStreamOutSize();
			ZSTD_DCtx* dctx = ZSTD_createDCtx();
			unsigned char* inputChunkBuffer = new unsigned char[inputChunkSize];
			unsigned char* outputChunkBuffer = new unsigned char[outputChunkSize];

			ZSTD_inBuffer zInput;
			ZSTD_outBuffer zOutput;

			zInput.src = inputChunkBuffer;
			zInput.size = inputChunkSize;
			zOutput.dst = outputChunkBuffer;
			zOutput.size = outputChunkSize;

			uint64_t residue = ifSize;
			DWORD dwSize;
			while (residue > 0)
			{
				(void)ReadFile(ifHandle, inputChunkBuffer, inputChunkSize, &dwSize, NULL);
				if (dwSize == 0)
				{
					break;
				}
				residue -= dwSize;
				if (dwSize < inputChunkSize)
				{
					//the last chunk
					zInput.size = dwSize;
				}
				zInput.pos = 0;
				zInput.pos = 0;
				while (zInput.pos < zInput.size)
				{
					zOutput.pos = 0;
					ZSTD_decompressStream(dctx, &zOutput, &zInput);
					WriteFile(ofHandle, outputChunkBuffer, zOutput.pos, NULL, NULL);
				}
			}

			FlushFileBuffers(ofHandle);
			CloseHandle(ifHandle);
			CloseHandle(ofHandle);
			ZSTD_freeDCtx(dctx);
			delete[] inputChunkBuffer;
			delete[] outputChunkBuffer;

			return true;
		}
	}
}

#endif //COMPRESSOR_H

/*EOF*/