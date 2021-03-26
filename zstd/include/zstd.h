/*
 * Copyright (c) 2016-2020, Yann Collet, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under both the BSD-style license (found in the
 * LICENSE file in the root directory of this source tree) and the GPLv2 (found
 * in the COPYING file in the root directory of this source tree).
 * You may select, at your option, one of the above-listed licenses.
 */
#if defined(__cplusplus)
extern "C"
{
#endif

#ifndef ZSTD_H
#define ZSTD_H

#include <limits.h> /* INT_MAX */
#include <stddef.h> /* size_t */

#if defined(ZSTD_DLL_EXPORT)
#define ZSTDLIB_API __declspec(dllexport)
#else
#define ZSTDLIB_API __declspec(dllimport)
#endif

#define ZSTD_VERSION_MAJOR 1
#define ZSTD_VERSION_MINOR 4
#define ZSTD_VERSION_RELEASE 6
#define ZSTD_VERSION_NUMBER (ZSTD_VERSION_MAJOR * 100 * 100 + ZSTD_VERSION_MINOR * 100 + ZSTD_VERSION_RELEASE)

#define ZSTD_LIB_VERSION ZSTD_VERSION_MAJOR.ZSTD_VERSION_MINOR.ZSTD_VERSION_RELEASE
#define ZSTD_QUOTE(str) #str
#define ZSTD_EXPAND_AND_QUOTE(str) ZSTD_QUOTE(str)
#define ZSTD_VERSION_STRING ZSTD_EXPAND_AND_QUOTE(ZSTD_LIB_VERSION)

#ifndef ZSTD_CLEVEL_DEFAULT
#define ZSTD_CLEVEL_DEFAULT 3
#endif

/* All magic numbers are supposed read/written to/from files/memory using little-endian convention */
#define ZSTD_MAGICNUMBER 0xFD2FB528
#define ZSTD_MAGIC_DICTIONARY 0xEC30A437
#define ZSTD_MAGIC_SKIPPABLE_START 0x184D2A50
#define ZSTD_MAGIC_SKIPPABLE_MASK 0xFFFFFFF0

#define ZSTD_BLOCKSIZELOG_MAX 17
#define ZSTD_BLOCKSIZE_MAX (1 << ZSTD_BLOCKSIZELOG_MAX)

#define ZSTD_CONTENTSIZE_UNKNOWN (0ULL - 1)
#define ZSTD_CONTENTSIZE_ERROR (0ULL - 2)

#define ZSTD_COMPRESSBOUND(srcSize) ((srcSize) + ((srcSize) >> 8) + (((srcSize) < (128 << 10)) ? (((128 << 10) - (srcSize)) >> 11) : 0))

  typedef enum
  {
    ZSTD_fast = 1,
    ZSTD_dfast = 2,
    ZSTD_greedy = 3,
    ZSTD_lazy = 4,
    ZSTD_lazy2 = 5,
    ZSTD_btlazy2 = 6,
    ZSTD_btopt = 7,
    ZSTD_btultra = 8,
    ZSTD_btultra2 = 9
  } ZSTD_strategy;

  typedef enum
  {
    ZSTD_c_compressionLevel = 100,
    ZSTD_c_windowLog = 101,
    ZSTD_c_hashLog = 102,
    ZSTD_c_chainLog = 103,
    ZSTD_c_searchLog = 104,
    ZSTD_c_minMatch = 105,
    ZSTD_c_targetLength = 106,
    ZSTD_c_strategy = 107,
    ZSTD_c_enableLongDistanceMatching = 160,
    ZSTD_c_ldmHashLog = 161,
    ZSTD_c_ldmMinMatch = 162,
    ZSTD_c_ldmBucketSizeLog = 163,
    ZSTD_c_ldmHashRateLog = 164,
    ZSTD_c_contentSizeFlag = 200,
    ZSTD_c_checksumFlag = 201,
    ZSTD_c_dictIDFlag = 202,
    ZSTD_c_nbWorkers = 400,
    ZSTD_c_jobSize = 401,
    ZSTD_c_overlapLog = 402,
    ZSTD_c_experimentalParam1 = 500,
    ZSTD_c_experimentalParam2 = 10,
    ZSTD_c_experimentalParam3 = 1000,
    ZSTD_c_experimentalParam4 = 1001,
    ZSTD_c_experimentalParam5 = 1002,
    ZSTD_c_experimentalParam6 = 1003,
    ZSTD_c_experimentalParam7 = 1004,
    ZSTD_c_experimentalParam8 = 1005,
    ZSTD_c_experimentalParam9 = 1006,
    ZSTD_c_experimentalParam10 = 1007,
    ZSTD_c_experimentalParam11 = 1008,
    ZSTD_c_experimentalParam12 = 1009
  } ZSTD_cParameter;

  typedef struct
  {
    size_t error;
    int lowerBound;
    int upperBound;
  } ZSTD_bounds;

  typedef enum
  {
    ZSTD_e_continue = 0,
    ZSTD_e_flush = 1,
    ZSTD_e_end = 2
  } ZSTD_EndDirective;

  typedef enum
  {
    ZSTD_reset_session_only = 1,
    ZSTD_reset_parameters = 2,
    ZSTD_reset_session_and_parameters = 3
  } ZSTD_ResetDirective;

  typedef enum
  {
    ZSTD_d_windowLogMax = 100,
    ZSTD_d_experimentalParam1 = 1000,
    ZSTD_d_experimentalParam2 = 1001,
    ZSTD_d_experimentalParam3 = 1002

  } ZSTD_dParameter;

  typedef struct ZSTD_inBuffer_s
  {
    const void *src;
    size_t size;
    size_t pos;
  } ZSTD_inBuffer;

  typedef struct ZSTD_outBuffer_s
  {
    void *dst;
    size_t size;
    size_t pos;
  } ZSTD_outBuffer;

  typedef struct ZSTD_CCtx_s ZSTD_CCtx;
  typedef struct ZSTD_DCtx_s ZSTD_DCtx;
  typedef ZSTD_CCtx ZSTD_CStream;
  typedef ZSTD_DCtx ZSTD_DStream;

  ZSTDLIB_API const char *ZSTD_versionString(void);
  ZSTDLIB_API unsigned ZSTD_isError(size_t code);
  ZSTDLIB_API const char *ZSTD_getErrorName(size_t code);
  ZSTDLIB_API ZSTD_bounds ZSTD_cParam_getBounds(ZSTD_cParameter cParam);
  ZSTDLIB_API ZSTD_bounds ZSTD_dParam_getBounds(ZSTD_dParameter dParam);

  ZSTDLIB_API size_t ZSTD_CStreamInSize(void);
  ZSTDLIB_API size_t ZSTD_CStreamOutSize(void);
  ZSTDLIB_API size_t ZSTD_DStreamInSize(void);
  ZSTDLIB_API size_t ZSTD_DStreamOutSize(void);
  ZSTDLIB_API ZSTD_CCtx *ZSTD_createCCtx(void);
  ZSTDLIB_API ZSTD_DCtx *ZSTD_createDCtx(void);
  ZSTDLIB_API size_t ZSTD_CCtx_reset(ZSTD_CCtx *cctx, ZSTD_ResetDirective reset);
  ZSTDLIB_API size_t ZSTD_DCtx_reset(ZSTD_DCtx *dctx, ZSTD_ResetDirective reset);
  ZSTDLIB_API size_t ZSTD_freeCCtx(ZSTD_CCtx *cctx);
  ZSTDLIB_API size_t ZSTD_freeDCtx(ZSTD_DCtx *dctx);
  ZSTDLIB_API size_t ZSTD_CCtx_setParameter(ZSTD_CCtx *cctx, ZSTD_cParameter param, int value);
  ZSTDLIB_API size_t ZSTD_DCtx_setParameter(ZSTD_DCtx *dctx, ZSTD_dParameter param, int value);
  ZSTDLIB_API size_t ZSTD_compressBound(size_t srcSize);
  ZSTDLIB_API unsigned long long ZSTD_getDecompressedSize(const void *src, size_t srcSize);
  ZSTDLIB_API size_t ZSTD_compressStream2(ZSTD_CCtx *cctx, ZSTD_outBuffer *output, ZSTD_inBuffer *input, ZSTD_EndDirective endOp);
  ZSTDLIB_API size_t ZSTD_decompressStream(ZSTD_DStream *zds, ZSTD_outBuffer *output, ZSTD_inBuffer *input);

#endif /* ZSTD_H */

#if defined(__cplusplus)
}
#endif
