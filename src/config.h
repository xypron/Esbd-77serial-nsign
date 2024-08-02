// SPDX-License-Identifier: Apache-2.0
/*
 * config file for nsig
 *
 * Copyright 2024 Beijing ESWIN Computing Technology Co., Ltd.
 *   Authors:
 *    liangshuang <liangshuang@eswincomputing.com>
 *
 */

#ifndef __CONFIG_H
#define __CONFIG_H
#include <stdio.h>
#include <ctype.h>
#include <string.h>

#if defined(WIN32) || defined(WINDOWS)
#include <windows.h>
#include <winsock.h>
#pragma comment(lib, "ws2_32.lib")
#define PATHCHAR '\\'
#define DELETEFILE(f) DeleteFile(f)
#define STRCASECMP(s1, s2) _stricmp(s1, s2)
#define SNPRINTF _snprintf

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long int uint64_t;
typedef short int16_t;
typedef int int32_t;

#define OS_CALLBACK __stdcall
#else
#include <arpa/inet.h>
#include <unistd.h>
#define PATHCHAR '/'
#define SNPRINTF snprintf
#define DELETEFILE(f) unlink(f)
#define STRCASECMP(s1, s2) strcasecmp(s1, s2)
#define OS_CALLBACK

#endif  // WIN32

#define GRK_SIGNINFO_SIZE (32)
#define GRK_SIGNINFO_SIZE_V2 (18 * sizeof(uint64_t))

#define IMAGE_GAP 0x200
#define IMAGE_MAX_COUNT 10
#define IMAGE_ALIGN 32

#define RSA_KEY_FREE(k)     \
    {                       \
        if (k) RSA_free(k); \
        (k) = NULL;         \
    }
#define MEM_BIO_FREE(m)     \
    {                       \
        if (m) BIO_free(m); \
        (m) = NULL;         \
    }
#define SIGNTURE_DATA_LEN 256

#define BTR_SHA256_DIGEST_SIZE 32
#define AVL_ROMCODE_CHECK_SIGN

#define SIGN_SIZE 256

#define BTR_SIGN_TYPE_PLAINTEXT 0
#define BTR_SIGN_TYPE_RSA_2048 1
#define BTR_SIGN_TYPE_RSA_4096 2
#define BTR_SIGN_TYPE_ECDSA 3

#define ESW_BOOTCHAIN_MAGIC 0x42575345
#define ESW_DIGEST_SHA256 0X00
#define ESW_DIGEST_SM3 0X01

/* Payload encrypted mothod */
#define SIGN_PAYLOAD_CRYPTO_PLAINT 0
#define SIGN_PAYLOAD_CRYPTO_AES 1
#define SIGN_PAYLOAD_CRYPTO_SM4 2
#define AES256_KEY_SIZE 32
#define AES128_KEY_SIZE 16
#define SYMM_ENCRYPT_KEY_SIZE 32
#define SYMM_ENCRYPT_IV_SIZE 16

#define NUMBER_OF_ONE_LINE 0x10
#define MAX_BUFFER_OF_ONE_LINE (NUMBER_OF_ONE_LINE * 2 + 11)

#define MAXTEMPBUF 512
#define BYTEPERLINE 8
#define ECBSIZE 36
#define HASH_SHA1_LEN 20
#define HASH_SHA256_LEN 32
#define HASH_SM3_LEN 32

#define CMD_CHIEF_SIGN_TEXT "chief_sign"
#define CMD_UART_SIGN_TEXT "uart_sign"
#define CMD_GENKEY_TEXT "genkey"

#define CMD_CHIEF_SIGN 0
#define CMD_UART_SIGN 1
#define CMD_GENKEY 2

#define DEF_KEYLEN 2048

#define ERR_OK 0
#define ERR_ECDSA -2019
#define ERR_GENERATE_KEY -2020
#define ERR_ARGUMENT -2021
#define ERR_OPENFILE -2022
#define ERR_HASH -2023
#define ERR_IO -2024
#define ERR_READPRIVATEKEY -2025
#define ERR_ALLOC -2026
#define ERR_PRIVATE_ENCRYPT -2027
#define ERR_GETECB -2028
#define ERR_WRITEPRIVATE -2029
#define ERR_DECRYPT -2030
#define ERR_FILESIZE -2031
#define ERR_NUMBER -2032
#define ERR_TIMEFORMAT -2033
#define ERR_GMTIME -2034
#define ERR_NOERROR -2035
#define ERR_CMD -2036
#define ERR_BINARY -2037
#define ERR_SIGNFILE -2038
#define ERR_WRITEPUBLIC -2039
#define ERR_FAILED -2040
#define ERR_CREATEDIR -2041
#define ERR_SELECTROOT -2042
#define ERR_WRITEFILE -2043
#define ERR_ENVELOPE -2044
#define ERR_SIGNATURE -2045
#define ERR_KEY -2046
#define ERR_GETRANDOM -2047
#define ERR_EXTAUTHENTICATE -2048
#define ERR_ERASEDIR -2049
#define ERR_ERASEFILE -2050
#define ERR_READFILE -2051
#define ERR_SELECTDIR -2052
#define ERR_ACTIVATEFILE -2053
#define ERR_SELECTFILE -2054
#define ERR_USBKEY -2055
#define ERR_CANCEL -2056
#define ERR_ARGSCOMBO -2057
#define ERR_DEVNOTFOUND -2058
#define ERR_UNKNOWN -2059
#define ERR_ARGPRIVATE -2060
#define ERR_MEM -2061
#define ERR_ECB -2062
#define ERR_UNALIGNED -2063
#define ERR_UNSUPPORTED -2064
#define ERR_INVALID_SIGN -2065
#define ERR_HEADER -2066
#define ERR_VERSION -2067
#define ERR_KEYIDX -2068
#define ERR_PARSEFILE -2069
#define ERR_PERMISSION -2070

#define GENKEY_BY_OPENSSL

#define RSA_KEY_SIZE 2048

#define MAGIC_DEFAULT 0xbb455357
#define RESERVED0_DEFAULT 0x0
#define LINK_ADDR_DEFAULT 0x0
#define VID_DEFAULT 0x0
#define RESERVED1_DEFAULT 0x0
#define LANG_DEFAULT 0x656e67
#define MID_DEFAULT 0x0
#define RESERVED2_DEFAULT 0x000000000000
#define DEVID_DEFAULT 0x0
#define PARAMS_DEFAULT 0x0
#define RESERVED3_DEFAULT 0x0
#define LOAD_INFO_DEFAULT 0x0
#define RESERVED4_DEFAULT 0x0

#endif  //__CONFIG_H
