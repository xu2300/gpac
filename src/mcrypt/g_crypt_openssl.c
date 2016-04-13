/*
*			GPAC - Multimedia Framework C SDK
*
*			Authors: Rodolphe Fouquet
*			Copyright (c) Motion Spell 2016
*					All rights reserved
*
*  This file is part of GPAC / crypto lib sub-project
*
*  GPAC is free software; you can redistribute it and/or modify
*  it under the terms of the GNU Lesser General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.
*
*  GPAC is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU Lesser General Public License for more details.
*
*  You should have received a copy of the GNU Lesser General Public
*  License along with this library; see the file COPYING.  If not, write to
*  the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
*
*/

#include "g_crypt_openssl.h"
#include <openssl/aes.h>

typedef struct {
	AES_KEY enc_key;
	AES_KEY dec_key;
	u8* block;
	u8* previous_ciphertext;
	u8* previous_cipher;
} Openssl_ctx_cbc;

/** CBC STUFF **/

GF_Err gf_crypt_init_openssl_cbc(GF_Crypt* td, void *key, const void *iv, int iv_size)
{
	GF_SAFEALLOC(td->context, Openssl_ctx_cbc);
	if (td->context == NULL) goto freeall;


	Openssl_ctx_cbc* ctx = (Openssl_ctx_cbc*)td->context;

	ctx->previous_ciphertext = gf_malloc(td->algo_block_size);
	ctx->previous_cipher = gf_malloc(td->algo_block_size);
	if(ctx->previous_ciphertext == NULL) goto freeall;
	if(ctx->previous_cipher == NULL) goto freeall;

	if (iv != NULL) {
		memcpy(ctx->previous_ciphertext, iv, td->mode_size);
	} else {
		memset(ctx->previous_ciphertext, 0, td->mode_size);
	}

	return GF_OK;

freeall:
	gf_free(ctx->previous_ciphertext);
	gf_free(ctx->previous_ciphertext);
	return GF_OUT_OF_MEM;
}

void gf_crypt_deinit_openssl_cbc(GF_Crypt* td)
{
	Openssl_ctx_cbc* ctx = (Openssl_ctx_cbc*)td->context;
	gf_free(ctx->previous_ciphertext);
	gf_free(ctx->previous_cipher);
}

void gf_set_key_openssl_cbc(GF_Crypt* td)
{
	Openssl_ctx_cbc* ctx = (Openssl_ctx_cbc*)td->context;
	AES_set_encrypt_key(td->keyword_given, td->key_size, &(ctx->enc_key));
	AES_set_decrypt_key(td->keyword_given, td->key_size, &(ctx->dec_key));
}

// Is size really needed? -> to investigate
GF_Err gf_crypt_set_state_openssl_cbc(GF_Crypt* td, const void *iv, int iv_size)
{
	Openssl_ctx_cbc* ctx = (Openssl_ctx_cbc* )td->context;
	memcpy(ctx->previous_ciphertext, iv, iv_size);
	memcpy(ctx->previous_cipher, iv, iv_size);
	return GF_OK;
}

GF_Err gf_crypt_get_state_openssl_cbc(GF_Crypt* td, void *iv, int *iv_size)
{

	Openssl_ctx_cbc* ctx = (Openssl_ctx_cbc*)td->context;
	*iv_size = td->algo_block_size;

	memcpy(iv, ctx->previous_ciphertext, td->algo_block_size);

	return GF_OK;
}


/** TODO: WIP - where do I store the result? I guess I should loop and concatenate output blocks somewhere **/
GF_Err gf_crypt_encrypt_openssl_cbc(GF_Crypt* td, u8 *plaintext, int len)
{
	Openssl_ctx_cbc* ctx = (Openssl_ctx_cbc*)td->context;
	int iteration;
	int numberOfIterations = 1 + len / td->algo_block_size;
	for (iteration = 0; iteration < numberOfIterations; ++iteration) {
		AES_cbc_encrypt(plaintext + iteration*td->algo_block_size, ctx->block, td->algo_block_size, &ctx->enc_key, ctx->previous_ciphertext, AES_ENCRYPT);
		memcpy((u8)plaintext + iteration*td->algo_block_size, ctx->block, td->algo_block_size);
		memcpy(ctx->previous_ciphertext, ctx->previous_cipher, td->algo_block_size);
	}

	return GF_OK;
}

/** TODO: WIP - where do I store the result? **/
GF_Err gf_crypt_decrypt_openssl_cbc(GF_Crypt* td, u8 *ciphertext, int len)
{
	Openssl_ctx_cbc* ctx = (Openssl_ctx_cbc*)td->context;

	int iteration;
	int numberOfIterations = 1 + len / td->algo_block_size;
	for (iteration = 0; iteration < numberOfIterations; ++iteration) {
		AES_cbc_encrypt(ciphertext + iteration*td->algo_block_size, ctx->block, td->algo_block_size, &ctx->dec_key, ctx->previous_ciphertext, AES_DECRYPT);
		memcpy((u8)ciphertext + iteration*td->algo_block_size, ctx->block, td->algo_block_size);
		memcpy(ctx->previous_ciphertext, ctx->previous_cipher, td->algo_block_size);
	}

	return GF_OK;
}

typedef struct {
	AES_KEY enc_key;
	AES_KEY dec_key;
	unsigned char* block;
	unsigned char* enc_counter;
	unsigned char* c_counter;
	unsigned int c_counter_pos;
} Openssl_ctx_ctr;


/** CTR STUFF **/

static void gf_set_key_openssl_ctr(GF_Crypt* td)
{
	Openssl_ctx_ctr* ctx = (Openssl_ctx_ctr*)td->context;
	AES_set_encrypt_key(td->keyword_given, td->key_size, &(ctx->enc_key));
	AES_set_decrypt_key(td->keyword_given, td->key_size, &(ctx->dec_key));
}

// Is size really needed? -> to investigate
static GF_Err gf_crypt_set_state_openssl_ctr(GF_Crypt* td, const void *iv, int iv_size)
{
	Openssl_ctx_ctr* ctx = (Openssl_ctx_ctr*)td->context;

	ctx->c_counter_pos = ((unsigned char*)iv)[0];
	memcpy(ctx->c_counter, &((unsigned char*)iv)[1], iv_size - 1);
	memcpy(ctx->enc_counter, &((unsigned char*)iv)[1], iv_size - 1);
	return GF_OK;
}

static GF_Err gf_crypt_get_state_openssl_ctr(GF_Crypt* td, void *iv, int *iv_size)
{
	Openssl_ctx_ctr* ctx = (Openssl_ctx_ctr*)td->context;

	*iv_size = td->algo_block_size + 1;

	((unsigned char *)iv)[0] = ctx->c_counter_pos;
	memcpy(&((unsigned char *)iv)[1], ctx->c_counter, td->algo_block_size);
	return GF_OK;
}

static GF_Err gf_crypt_init_openssl_ctr(GF_Crypt* td, void *key, const void *iv, int iv_size)
{
	GF_SAFEALLOC(td->context, Openssl_ctx_ctr);
	Openssl_ctx_ctr* ctx = (Openssl_ctx_ctr*)td->context;

	/* For ctr */
	ctx->c_counter_pos = 0;

	ctx->c_counter = gf_malloc(td->algo_block_size);
	if (ctx->c_counter == NULL) goto freeall;

	ctx->enc_counter = gf_malloc(td->algo_block_size);
	if (ctx->enc_counter == NULL) goto freeall;

	if (iv != NULL) {
		memcpy(ctx->enc_counter, iv, td->algo_block_size);
		memcpy(ctx->c_counter, iv, td->algo_block_size);
	}
	/* End ctr */

	return GF_OK;

freeall:
	gf_free(ctx->c_counter);
	gf_free(ctx->enc_counter);
	return GF_OUT_OF_MEM;
}


/** TODO: WIP - where do I store the result? Did I map the members correctly? **/
static GF_Err gf_crypt_encrypt_openssl_ctr(GF_Crypt* td, u8 *plaintext, int len)
{
	Openssl_ctx_ctr* ctx = (Openssl_ctx_ctr*)td->context;	
	int iteration;
	return GF_OK;
}

/** TODO: WIP - where do I store the result? **/
static GF_Err gf_crypt_decrypt_openssl_ctr(GF_Crypt* td, u8 *ciphertext, int len)
{
	Openssl_ctx_ctr* ctx = (Openssl_ctx_ctr*)td->context;		
	int iteration;
	int numberOfIterations = 1 + len / td->algo_block_size;
	for (iteration = 0; iteration < numberOfIterations; ++iteration) {
		AES_ctr128_encrypt((const u8)ciphertext + iteration*td->algo_block_size, ctx->block, len, &(ctx->enc_key), ctx->c_counter, ctx->enc_counter, ctx->c_counter_pos);
		memcpy((u8)ciphertext + iteration*td->algo_block_size, ctx->block, td->algo_block_size);
	}
	return GF_OK;
}



GF_Err open_openssl(GF_Crypt* td, GF_CRYPTO_MODE mode)
{
	td->mode = mode;
	switch (td->mode) {
	case GF_CBC:
		td->_init_crypt = gf_crypt_init_openssl_cbc;
		td->_set_key = gf_set_key_openssl_cbc;
		td->_crypt = gf_crypt_encrypt_openssl_cbc;
		td->_decrypt = gf_crypt_decrypt_openssl_cbc;
		td->_get_state = gf_crypt_get_state_openssl_cbc;
		td->_set_state = gf_crypt_set_state_openssl_cbc;
		break;
	case GF_CTR:
		td->_init_crypt = gf_crypt_init_openssl_ctr;
		td->_set_key = gf_set_key_openssl_ctr;
		td->_crypt = gf_crypt_encrypt_openssl_ctr;
		td->_decrypt = gf_crypt_decrypt_openssl_ctr;
		td->_get_state = gf_crypt_get_state_openssl_ctr;
		td->_set_state = gf_crypt_set_state_openssl_ctr;
		break;
	default:
		return GF_BAD_PARAM;
		break;

	}

	td->algo = GF_AES_128;
	td->key_size = 16;
	td->is_block_algo = 1;
	td->algo_block_size = AES_BLOCK_SIZE;

	td->has_IV = 1;
	td->is_block_mode = 1;
	td->is_block_algo_mode = 1;

	return GF_OK;
}
