/*
*			GPAC - Multimedia Framework C SDK
*
*			Authors: Rodolphe Fouquet
*			Copyright (c) Telecom ParisTech 2000-2016
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
#ifndef G_CRYPT_OPENSSL
#define G_CRYPT_OPENSSL

#include <gpac/internal/crypt_dev.h>
#include <openssl/aes.h>

GF_Err open_openssl(GF_Crypt* td, GF_CRYPTO_MODE mode);


static void gf_set_key_openssl_cbc(GF_Crypt* td);
static GF_Err gf_crypt_set_state_openssl_cbc(GF_Crypt* td, const void *iv, int size);
static GF_Err gf_crypt_get_state_openssl_cbc(GF_Crypt* td, void *iv, int *size);
static GF_Err gf_crypt_init_openssl_cbc(GF_Crypt* td, void *key, const void *IV);
static GF_Err gf_crypt_encrypt_openssl_cbc(GF_Crypt* td, void *plaintext, int len);
static GF_Err gf_crypt_decrypt_openssl_cbc(GF_Crypt* td, void *ciphertext, int len);


static void gf_set_key_openssl_ctr(GF_Crypt* td);
static GF_Err gf_crypt_set_state_openssl_ctr(GF_Crypt* td, const void *iv, int size);
static GF_Err gf_crypt_get_state_openssl_ctr(GF_Crypt* td, void *iv, int *size);
static GF_Err gf_crypt_init_openssl_ctr(GF_Crypt* td, void *key, const void *IV);
static GF_Err gf_crypt_encrypt_openssl_ctr(GF_Crypt* td, void *plaintext, int len);
static GF_Err gf_crypt_decrypt_openssl_ctr(GF_Crypt* td, void *ciphertext, int len);



#endif /* G_CRYPT_OPENSSL */