 /*********************************************************************
 * Copyright (c) 2016 Pieter Wuille                                   *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or https://opensource.org/licenses/mit-license.php.   *
 **********************************************************************/

#include <Windows.h>
#include <stdint.h>

typedef struct {
    uint16_t slice[8];
} AES_state;

typedef struct {
    AES_state rk[15];
} AES256_ctx;

typedef struct {
    AES256_ctx ctx;
    uint8_t iv[16];
} AES256_CBC_ctx;


void AES256_CBC_init(AES256_CBC_ctx* ctx, const unsigned char* key16, const uint8_t* iv);
boolean AES256_CBC_encrypt(AES256_CBC_ctx* ctx, const unsigned char* plain, size_t plainsize, PBYTE* encrypted);
boolean AES256_CBC_decrypt(AES256_CBC_ctx* ctx, const unsigned char* encrypted, size_t ciphersize, PBYTE* plain);
